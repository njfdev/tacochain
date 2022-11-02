use chrono::prelude::*;
use libp2p::{
    core::upgrade,
    futures::StreamExt,
    mplex,
    noise::{Keypair, NoiseConfig, X25519Spec},
    swarm::{Swarm, SwarmBuilder},
    tcp::TokioTcpConfig,
    Transport, identity::ed25519::{PublicKey, self},
};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wallet::Transaction;
use std::time::Duration;
use tokio::{
    io::{stdin, AsyncBufReadExt, BufReader},
    select, spawn,
    sync::mpsc,
    time::sleep,
};

// What number should be at the start of the hash in binary.
// Increase this to make mining more difficult. We need this
// to create a proof of work (PoW) system.
const DIFFICULTY_PREFIX: &str = "0000000000000000";

mod p2p;
mod wallet;

// The app just stores out blockchain
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct App {
    pub blocks: Vec<Block>,
    pub pending_transactions: Vec<Transaction>,
}

// We create out block with the necessary information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: i64,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
}

impl Block {
    // Create a new block
    pub fn new(id: u64, previous_hash: String, transactions: Vec<Transaction>) -> Self {
        // Get a time at the block creation
        let now = Utc::now();
        // Mine the block with our block data and get our nonce and hash
        let (nonce, hash) = mine_block(id, now.timestamp(), &previous_hash, &transactions);
        // Return a new instance of a Block
        Self {
            id,
            hash,
            timestamp: now.timestamp(),
            previous_hash,
            transactions,
            nonce,
        }
    }
}

// Generate a SHA256 hash based off of the block data
fn calculate_hash(id: u64, timestamp: i64, previous_hash: &str, data_hash: &str, nonce: u64) -> Vec<u8> {
    // Convert our data to a json object
    let data = serde_json::json!({
        "id": id,
        "previous_hash": previous_hash,
        "data_hash": data_hash,
        "timestamp": timestamp,
        "nonce": nonce
    });
    // Create our hashing instance
    let mut hasher = Sha256::new();
    // Create a new hash with the json object in bytes
    hasher.update(data.to_string().as_bytes());
    // Return ownership of the hash (as the type Vec<u8>)
    hasher.finalize().as_slice().to_owned()
}

fn transactions_to_hash(transactions: &[Transaction]) -> String {
    // We create a hash of the data to pass to our calculate_hash function.
    // We use a hash because they will always be 64 characters long even if
    // the actually data is 1 million characters long. This makes the mining
    // process the same speed for a lot of data or a little bit of data.
    let mut hasher = Sha256::new();
    let transactions_in_bytes: Vec<u8> = transactions.iter().map(|transaction| -> Vec<u8> { Transaction::transaction_to_vec(transaction) }).collect::<Vec<_>>().concat();
    hasher.update(transactions_in_bytes);
    // Formate the hash as a hex string
    format!("{:X}", hasher.finalize())
}

// Brute force finding the nonce in a process called mining
fn mine_block(id: u64, timestamp: i64, previous_hash: &str, transactions: &Vec<Transaction>) -> (u64, String) {
    info!("mining block...");
    let mut nonce = 0;

    let data_hash = transactions_to_hash(&transactions);

    // Loop through nonces and check if the hash starts with the DIFFICULTY_PREFIX
    loop {
        // Every 100,000 loops, output the nonce
        if nonce % 100_000 == 0 {
            info!("nonce: {}", nonce);
        }
        // Calculate the hash
        let hash = calculate_hash(id, timestamp, previous_hash, &data_hash, nonce);
        // Convert the hash to binary
        let binary_hash = hash_to_binary_representation(&hash);
        // Check if the binary hash starts with the nonce
        if binary_hash.starts_with(DIFFICULTY_PREFIX) {
            // If so, announce the mined nonce and hash
            info!(
                "mined! nonce: {}, hash: {}, binary hash: {}",
                nonce,
                hex::encode(&hash),
                binary_hash
            );
            // return the found nonce and hash
            return (nonce, hex::encode(hash));
        }
        nonce += 1;
    }
}

// Convert a hash (array of u8's) to binary (as a String)
fn hash_to_binary_representation(hash: &[u8]) -> String {
    // Create an empty string to add out binary bits to
    let mut res: String = String::default();
    // Go through each character in the hash
    for c in hash {
        // Add the char to the new string with the formatting as a
        // binary number with 0 padding up to 8 bits.
        res.push_str(&format!("{:08b}", c));
    }
    res
}

impl App {
    // Create a new App
    fn new() -> Self {
        // Initialize the app with an empty
        Self { blocks: vec![], pending_transactions: vec![] }
    }

    // Create a genesis block
    fn genesis(&mut self, creator_address: &PublicKey) {
        let from_address = [0; 32];
        let to_address: [u8; 32] = creator_address.encode();
        let amount: u64 = 100;

        // Create our genesis block
        let genesis_block = Block::new(
            0, 
            String::from("genesis"), 
            vec![
                Transaction {
                    from_address,
                    to_address,
                    amount,
                    signature: vec![0]
                }
            ]
        );
        // Add our block without running it through try_add_block().
        // We do this because the previous_hash is invalid as no
        // previous block exists.
        self.blocks.push(genesis_block);
    }

    // Add a block to the chain if it is valid
    fn try_add_block(&mut self, block: Block) {
        // Get the latest block
        let latest_block = self.blocks.last().expect("there is at least one block");
        // Check if the block is valid and add it if it is
        if self.is_block_valid(&block, latest_block) {
            self.blocks.push(block);
        } else {
            error!("could not add block - invalid");
        }
    }

    // Add a block to the chain if it is valid
    fn try_add_transaction(&mut self, transaction: Transaction) {
        self.pending_transactions.push(transaction);
    }

    // Check if a block is valid
    fn is_block_valid(&self, block: &Block, previous_block: &Block) -> bool {
        // The previous block hash should be this block's previous_hash
        if block.previous_hash != previous_block.hash {
            warn!("block with id: {} has wrong previous hash", block.id);
            return false;
        // The hash should start with the difficulty prefix
        } else if !hash_to_binary_representation(
            &hex::decode(&block.hash).expect("can decode from hex"),
        )
        .starts_with(DIFFICULTY_PREFIX)
        {
            warn!("block with id: {} has invalid difficulty", block.id);
            return false;
        // The current id should be 1 more than the previous id.
        } else if block.id != previous_block.id + 1 {
            warn!(
                "block with id: {} is not the next block after the latest: {}",
                block.id, previous_block.id
            );
            return false;
        // The block's hash should actually be the computed hash.
        } else if hex::encode(calculate_hash(
            block.id,
            block.timestamp,
            &block.previous_hash,
            &transactions_to_hash(&block.transactions),
            block.nonce,
        )) != block.hash
        {
            warn!("block with id: {} has invalid hash", block.id);
            return false;
        }
        // If none of these conditions are true, then the block is valid.
        true
    }

    // Check if a chain of blocks are valid
    fn is_chain_valid(&self, chain: &[Block]) -> bool {
        // For every block in the chain, check if it is valid
        for i in 0..chain.len() {
            if i == 0 {
                continue;
            }
            let first = chain.get(i - 1).expect("has to exist");
            let second = chain.get(i).expect("has to exist");
            if !self.is_block_valid(second, first) {
                // Return false if any block if invalid
                return false;
            }
        }
        // Return true if all blocks are valid
        true
    }

    // We always choose the longest valid chain
    fn choose_chain(&mut self, local: Vec<Block>, remote: Vec<Block>) -> Vec<Block> {
        // Run checks to see if the remote and local chains are valid
        let is_local_valid = self.is_chain_valid(&local);
        let is_remote_valid = self.is_chain_valid(&remote);

        // If both chains are valid, then choose the longest one
        if is_local_valid && is_remote_valid {
            if local.len() >= remote.len() {
                local
            } else {
                remote
            }
        // Choose the remote chain if it is the only valid chain
        } else if is_remote_valid && !is_local_valid {
            remote
        // Choose the local chain if it is the only valid chain
        } else if !is_remote_valid && is_local_valid {
            local
        // If both chains are invalid, something has gone horribly wrong
        } else {
            panic!("local and remote chains are both invalid");
        }
    }
}

// Use the tokio runtime
#[tokio::main]
async fn main() {
    // Initialize the logger so we can see output
    pretty_env_logger::init();

    let wallet = wallet::Wallet::new();

    info!("Wallet Id: {}", hex::encode(wallet.keypair.public().encode()));

    // Announce the local peer id
    info!("Peer Id: {}", p2p::PEER_ID.clone());
    // Setup our response_sender and init_sender
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel();
    let (init_sender, mut init_rcv) = mpsc::unbounded_channel();

    // Get our auth keys (public and private)
    let auth_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&p2p::KEYS)
        .expect("can create auth keys");

    // Create a transport with authentication
    let transp = TokioTcpConfig::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    // Create a new instance of our AppBehaviour
    let behaviour = p2p::AppBehaviour::new(App::new(), response_sender, init_sender.clone()).await;

    // Create a swarm instance. Allows us to interact with our peer to peer network.
    let mut swarm = SwarmBuilder::new(transp, behaviour, *p2p::PEER_ID)
        .executor(Box::new(|fut| {
            spawn(fut);
        }))
        .build();

    // Create a input reader using Tokio
    let mut stdin = BufReader::new(stdin()).lines();

    // Start listening on every port
    Swarm::listen_on(
        &mut swarm,
        "/ip4/0.0.0.0/tcp/0"
            .parse()
            .expect("can get a local socket"),
    )
    .expect("swarm can be started");

    // Start a new asynchronous task using Tokio
    spawn(async move {
        sleep(Duration::from_secs(1)).await;
        info!("sending init event");
        // Send the event announcing initialization of self
        init_sender.send(true).expect("can send init event");
    });

    // Run the event loop
    loop {
        // Get the current Event Type
        let evt = {
            // The select macro waits until a function completes, then it cancels the rest.
            select! {
                // Wait for user to press enter, then return an event type of input with the user input
                line = stdin.next_line() => Some(p2p::EventType::Input(line.expect("can get line").expect("can read line from stdin"))),
                // Wait until a response has been received and then return event type of LocalChainResponse
                // with the received response.
                response = response_rcv.recv() => {
                    Some(p2p::EventType::LocalAppResponse(response.expect("response exists")))
                },
                // Wait until there is an init event then return the event type of init
                _init = init_rcv.recv() => {
                    Some(p2p::EventType::Init)
                }
                // If there is a swarm event, handle it.
                event = swarm.select_next_some() => {
                    match event {
                        // If a peer was banned, announce it
                        libp2p::swarm::SwarmEvent::BannedPeer { peer_id, endpoint: _ } => info!("Peer {} was banned", peer_id),
                        // otherwise do nothing
                        _ => (),
                    }
                    // Return None type
                    None
                },
            }
        };

        // If the event type is not None, then handle it
        if let Some(event) = evt {
            match event {
                // Init events
                p2p::EventType::Init => {
                    // Get a list of all the peers
                    let peers = p2p::get_list_peers(&swarm);

                    info!("connected nodes: {}", peers.len());
                    // If there are other peers, than get their blockchain
                    if !peers.is_empty() {
                        // Create a request to get the chain from the last peer in our list
                        let req = p2p::LocalAppRequest {
                            from_peer_id: peers
                                .iter()
                                .last()
                                .expect("at least one peer")
                                .to_string(),
                        };

                        // Convert our request object to json
                        let json = serde_json::to_string(&req).expect("can jsonify request");
                        // Publish our request on our network
                        swarm
                            .behaviour_mut()
                            .floodsub
                            .publish(p2p::APP_TOPIC.clone(), json.as_bytes());
                    // Otherwise, this is the only node
                    } else {
                        // because there are no other nodes to get the chain from, create the chain locally
                        swarm.behaviour_mut().app.genesis(&wallet.keypair.public());
                    }
                }
                // If a peer is requesting our chain
                p2p::EventType::LocalAppResponse(resp) => {
                    // Convert the response to json then send it
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm
                        .behaviour_mut()
                        .floodsub
                        .publish(p2p::APP_TOPIC.clone(), json.as_bytes());
                }
                // If the user made input
                p2p::EventType::Input(line) => match line.as_str() {
                    // List all the peers
                    "peers" => p2p::handle_print_peers(&swarm),
                    // List the blockchain
                    cmd if cmd.starts_with("ls b") => p2p::handle_print_chain(&swarm),
                    // List pending_transactions
                    cmd if cmd.starts_with("ls t") => p2p::handle_print_transactions(&swarm),
                    // create a block
                    cmd if cmd.starts_with("send ") => p2p::send_transaction(cmd, &wallet, &mut swarm),
                    // Error if the command is not valid
                    _ => error!("unknown command"),
                },
            }
        }
    }
}