use std::fmt::Debug;

use libp2p::identity::ed25519::{self, PublicKey};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Transaction {
    #[serde(with = "hex")]
    pub from_address: [u8; 32],
    #[serde(with = "hex")]
    pub to_address: [u8; 32],
    pub amount: u64,
    #[serde(with = "hex")]
    pub signature: Vec<u8>
}

impl Transaction {
    pub fn new(wallet: &Wallet, to_address: &PublicKey, amount: u64) -> Self {

        let from_address = wallet.keypair.public();

        let transaction_in_bytes = Self::transaction_metadata_to_bytes(&from_address, &to_address, &amount);
            
        let signature = wallet.keypair.sign(&transaction_in_bytes);

        Self {
            from_address: from_address.encode(),
            to_address: to_address.encode(),
            amount,
            signature
        }
    }

    pub fn transaction_metadata_to_bytes(from_address: &ed25519::PublicKey, to_address: &ed25519::PublicKey, amount: &u64) -> [u8; 72] {
        let from_address = from_address.encode();
        let to_address = to_address.encode();

        let mut transaction_in_bytes: Vec<u8> = from_address.clone().to_vec();
        transaction_in_bytes.extend_from_slice(&to_address);
        transaction_in_bytes.extend_from_slice(&amount.to_le_bytes());

        transaction_in_bytes.try_into().expect("transaction metadata should result in 72 bytes")
    }

    pub fn transaction_to_vec(transaction: &Transaction) -> Vec<u8> {
        let Transaction {from_address, to_address, amount, signature} = transaction;

        let mut transaction_in_bytes: Vec<u8> = from_address.clone().to_vec();
        transaction_in_bytes.extend_from_slice(to_address);
        transaction_in_bytes.extend_from_slice(&amount.to_le_bytes());
        transaction_in_bytes.extend_from_slice(signature);

        transaction_in_bytes
    }
}