use libp2p::identity::ed25519::{self, PublicKey};

pub struct Wallet {
    pub keypair: ed25519::Keypair,
}

impl Wallet {
    pub fn new() -> Self {

        let keypair = ed25519::Keypair::generate();

        Self {
            keypair
        }
    }
}

pub struct Transaction {
    from_address: [u8; 32],
    to_address: [u8; 32],
    amount: u64,
    signature: Vec<u8>
}

impl Transaction {
    pub fn new(wallet: &Wallet, to_address: &PublicKey, amount: u64) -> Self {

        let from_address = wallet.keypair.public().encode();
        let to_address = to_address.encode();

        let transaction_in_bytes: [u8; 72] = ::byte_strings::concat_bytes!(
            from_address, 
            to_address, 
            amount.to_le_bytes()
        );

        let signature = wallet.keypair.sign(&transaction_in_bytes);

        Self {
            from_address,
            to_address,
            amount,
            signature
        }
    }
}