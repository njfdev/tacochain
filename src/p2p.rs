use crate::wallet::{Wallet, Transaction};

use super::{App, Block};
use libp2p::{
    floodsub::{Floodsub, FloodsubEvent, Topic},
    identity::{self, ed25519::{self, PublicKey}},
    mdns::{Mdns, MdnsEvent},
    swarm::{NetworkBehaviourEventProcess, Swarm},
    NetworkBehaviour, PeerId,
};
use log::{error, info, warn};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::sync::mpsc;

// Create a public and private keypair for authenticating on the peer to peer network
pub static KEYS: Lazy<identity::Keypair> = Lazy::new(identity::Keypair::generate_ed25519);
// Based on the public key, generate a peer id others will refer to you as
pub static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public()));
// We have 2 topics for our p2p network so we know what to do when we get data
pub static CHAIN_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("chains"));
pub static BLOCK_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("blocks"));
pub static TRANSACTION_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("transactions"));

// When we request for someone's blockchain, they will give us their blocks for the
// blockchain and we will need their peer id
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainResponse {
    pub blocks: Vec<Block>,
    pub receiver: String,
}

// We someone requests our local blockchain, we will need to know where to send it
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalChainRequest {
    pub from_peer_id: String,
}

// When running our app, our event loop will need to know what is happening. These states
// could be sending our local blockchain, getting command line input from the user, or
// initiating a new blockchain.
pub enum EventType {
    LocalChainResponse(ChainResponse),
    Input(String),
    Init,
}

// This struct is where we will have the behaviour of our application. Floodsub is the
// tool for subscribing to events from other peers on the network. Mdns stands for Multicast
// DNS which allows for discovering other peers on the local network only. Then we also 
// store our app. Response sender is the sender to use when responding for events. Init
// sender is the sender to use when announcing initialization of the local chain.
#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub floodsub: Floodsub,
    pub mdns: Mdns,
    #[behaviour(ignore)]
    pub response_sender: mpsc::UnboundedSender<ChainResponse>,
    #[behaviour(ignore)]
    pub init_sender: mpsc::UnboundedSender<bool>,
    #[behaviour(ignore)]
    pub app: App,
}

impl AppBehaviour {
    pub async fn new(
        app: App,
        response_sender: mpsc::UnboundedSender<ChainResponse>,
        init_sender: mpsc::UnboundedSender<bool>,
    ) -> Self {
        // Create a new instance of AppBehaviour
        let mut behaviour = Self {
            app,
            // We need our peer id so others know who to subscribe to
            floodsub: Floodsub::new(*PEER_ID),
            // Wait for Mdns to setup with a default config
            mdns: Mdns::new(Default::default())
                .await
                .expect("can create mdns"),
            response_sender,
            init_sender,
        };
        // Subscribe to both of our network topics
        behaviour.floodsub.subscribe(CHAIN_TOPIC.clone());
        behaviour.floodsub.subscribe(BLOCK_TOPIC.clone());
        behaviour.floodsub.subscribe(TRANSACTION_TOPIC.clone());

        // Return ownership of the AppBehaviour instance
        behaviour
    }
}

// Handle incoming events related to Floodsub (events received from subscribers)
impl NetworkBehaviourEventProcess<FloodsubEvent> for AppBehaviour {
    // Modify the behaviour when floodsub receives an event
    fn inject_event(&mut self, event: FloodsubEvent) {
        // if let syntax can be confusing so there is a great explanation in the rust
        // book (https://doc.rust-lang.org/book/ch06-03-if-let.html).
        // If event is the type of Floodsub::Message(msg), then continue.
        if let FloodsubEvent::Message(msg) = event {
            // Parse an array of bytes (Vec<u8>) into json and try to Serialize it into
            // ChainResponse. If this returns and Error, it means that the incoming data
            // is not compatible with ChainResponse so continue.
            if let Ok(resp) = serde_json::from_slice::<ChainResponse>(&msg.data) {
                // Check if we are the intended recipient of the msg
                if resp.receiver == PEER_ID.to_string() {
                    info!("Response from {}:", msg.source);
                    // For every block in the received chain, print in to the console
                    resp.blocks.iter().for_each(|r| info!("{:?}", r));

                    // Pick a chain to use and then set it as the local chain.
                    self.app.blocks = self.app.choose_chain(self.app.blocks.clone(), resp.blocks);
                }
            // Check if the incoming data is of the type LocalChainRequest
            } else if let Ok(resp) = serde_json::from_slice::<LocalChainRequest>(&msg.data) {
                let peer_id = resp.from_peer_id;
                // Check if peer is requesting our local chain
                if PEER_ID.to_string() == peer_id {
                    info!("sending local chain to {}", msg.source.to_string());
                    // Send our local blockchain to the peer that was requesting it. If it
                    // errored, then announce it.
                    if let Err(e) = self.response_sender.send(ChainResponse {
                        blocks: self.app.blocks.clone(),
                        receiver: msg.source.to_string(),
                    }) {
                        error!("error sending response via channel, {}", e);
                    }
                }
            // Check if the incoming data is of the type Block
            } else if let Ok(block) = serde_json::from_slice::<Block>(&msg.data) {
                info!("received new block from {}", msg.source.to_string());
                // Attempt at adding the incoming block
                self.app.try_add_block(block);
            } else if let Ok(new_transaction) = serde_json::from_slice::<Transaction>(&msg.data) {
                info!("received new transaction from {}", msg.source.to_string());
                // Attempt at adding the incoming block
                self.app.try_add_transaction(new_transaction);
            }
        }
    }
}

// Handle mDNS events
impl NetworkBehaviourEventProcess<MdnsEvent> for AppBehaviour {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(discovered_list) => {
                // If mDNA discovered new peers, add it to floodsub
                for (peer, _addr) in discovered_list {
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(expired_list) => {
                // Go through the list of expired peers, and remove it from floodsub
                // if we have it.
                for (peer, _addr) in expired_list {
                    if !self.mdns.has_node(&peer) {
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

// Based on the p2p swarm, return all the peers
pub fn get_list_peers(swarm: &Swarm<AppBehaviour>) -> Vec<String> {
    // Get all discovered nodes
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut unique_peers = HashSet::new();
    // Add nodes to a hashmap
    for peer in nodes {
        unique_peers.insert(peer);
    }
    // convert the hashmap to a Vec<String> and return
    unique_peers.iter().map(|p| p.to_string()).collect()
}

// Print the peers based on a p2p swarm
pub fn handle_print_peers(swarm: &Swarm<AppBehaviour>) {
    info!("Discovered Peers:");
    // Get all the peers
    let peers = get_list_peers(swarm);
    // For each peer, print it
    peers.iter().for_each(|p| info!("{}", p));
}

// Print the blockchain based on the p2p swarm
pub fn handle_print_chain(swarm: &Swarm<AppBehaviour>) {
    info!("Local Blockchain:");
    // Get all the blocks in the chain and parse them into formatted json
    let pretty_json =
        serde_json::to_string_pretty(&swarm.behaviour().app.blocks).expect("can jsonify blocks");
    info!("{}", pretty_json);
}

// Print the blockchain based on the p2p swarm
pub fn handle_print_transactions(swarm: &Swarm<AppBehaviour>) {
    info!("Local Pending Transactions:");
    // Get all the blocks in the chain and parse them into formatted json
    let pretty_json =
        serde_json::to_string_pretty(&swarm.behaviour().app.pending_transactions).expect("can jsonify blocks");
    info!("{}", pretty_json);
}

// Create a new block based on the input
pub fn send_transaction(cmd: &str, wallet: &Wallet, swarm: &mut Swarm<AppBehaviour>) {
    // the create block command is "create b", so we want to remove this
    // prefix and get the data. If this fails then that means the string
    // did not start with "create b".
    if let Some(data) = cmd.strip_prefix("send ") {
        let transaction_data: Vec<&str> = data.split(" to ").collect::<Vec<&str>>();

        if transaction_data.len() != 2 {
            warn!("Transaction should be in this format: send {{amount}} to {{address}}");
            return;
        }

        let amount: u64 = transaction_data[0].parse().unwrap();
        let transaction_decode_result = hex::decode(&transaction_data[1]);
        let to_address_bytes: &Vec<u8> = match &transaction_decode_result {
            Err(error) => {
                warn!("Address was not formatted in hex: {}", error);
                return;
            }
            Ok(address) => address
        };
        let to_address: PublicKey = match PublicKey::decode(to_address_bytes) {
            Err(error) => {
                warn!("Could not send transaction to {}", error);
                return;
            }
            Ok(address) => address
        };

        // Get a mutable instance to AppBehaviour
        let behaviour = swarm.behaviour_mut();
        // Create a new valid transaction with the inputted data
        let transaction = Transaction::new(
            wallet,
            &to_address,
            amount,
        );
        // Convert the block to json so we can send in over the p2p network.
        let json = serde_json::to_string(&transaction).expect("can jsonify request");
        // Add this block to our chain
        behaviour.app.pending_transactions.push(transaction);
        info!("broadcasting new transaction");
        // Use floodsub to publish our block to all subscribers
        behaviour
            .floodsub
            .publish(TRANSACTION_TOPIC.clone(), json.as_bytes());
    }
}

pub fn handle_create_block(cmd: &str, swarm: &mut Swarm<AppBehaviour>) {
    // the create block command is "create b", so we want to remove this
    // prefix and get the data. If this fails then that means the string
    // did not start with "create b".
    if let Some(data) = cmd.strip_prefix("cb") {
        // Get a mutable instance to AppBehaviour
        let behaviour = swarm.behaviour_mut();
        // Get a reference of the latest block
        let latest_block = behaviour
            .app
            .blocks
            .last()
            .expect("there is at least one block");
        // Create a new valid block with the inputted data
        let block = Block::new(
            latest_block.id + 1,
            latest_block.hash.clone(),
            vec![],
        );
        // Convert the block to json so we can send in over the p2p network.
        let json = serde_json::to_string(&block).expect("can jsonify request");
        // Add this block to our chain
        behaviour.app.blocks.push(block);
        info!("broadcasting new block");
        // Use floodsub to publish our block to all subscribers
        behaviour
            .floodsub
            .publish(BLOCK_TOPIC.clone(), json.as_bytes());
    }
}