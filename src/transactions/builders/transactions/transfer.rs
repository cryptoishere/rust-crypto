use anyhow;
use hex;

use crate::configuration::fees;
use crate::enums::assets::Asset;
use crate::enums::{TransactionGroup, TransactionType};
use crate::identities::public_key;
use crate::transactions::transaction::Transaction;
use crate::utils::slot;

pub fn build_transfer(
    passphrase: &str,
    second_passphrase: Option<&str>,
    recipient_id: &str,
    amount: u64,
    vendor_field: &str,
    nonce: u64,
    fee: u64,
    version: u8,
    network: u8,
) -> Result<Transaction, anyhow::Error> {
    let mut transaction = create(TransactionType::Transfer);

    transaction.recipient_id = recipient_id.to_owned();
    transaction.amount = amount;
    transaction.vendor_field = vendor_field.to_owned();
    transaction.fee = fee;
    transaction.nonce = nonce;
    transaction.version = version;
    transaction.network = network;
    transaction.type_group = TransactionGroup::Core as u32;
    transaction.timestamp = slot::get_time();
    transaction.hash(passphrase)?;

    transaction.id = transaction.get_id()?;

    transaction = transaction.sign_schnorr(passphrase)?;

    if let Some(passphrase) = second_passphrase {
        log::debug!("Second sign applied.");
        transaction = transaction.second_sign_schnorr(passphrase)?;
    }

    Ok(transaction)
}

pub fn build_second_signature_registration(
    passphrase: &str,
    second_passphrase: &str,
    nonce: u64,
    version: u8,
    network: u8,
) -> Result<Transaction, anyhow::Error> {
    let mut transaction = create(TransactionType::SecondSignature);

    transaction.version = version;
    transaction.network = network;
    transaction.type_group = TransactionGroup::Core as u32;
    transaction.nonce = nonce;

    transaction.amount = 0;

    transaction.recipient_id = String::new();

    transaction.asset = Asset::Signature {
        public_key: hex::encode(
            public_key::from_passphrase(second_passphrase)?
                .serialize()
                .to_vec(),
        ),
    };

    transaction.timestamp = slot::get_time();
    transaction.hash(passphrase)?;

    transaction.id = transaction.get_id()?;

    transaction = transaction.sign_schnorr(passphrase)?;

    Ok(transaction)
}

fn create(transaction_type: TransactionType) -> Transaction {
    let mut transaction = Transaction::default();
    transaction.type_id = transaction_type;
    transaction.fee = fees::get(transaction_type).unwrap();
    transaction
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn second_signature_schnorr() {
        let transaction = build_transfer(
            "doll maple globe organ raccoon common only pause neglect athlete prize hurry",
            Some("youth soda robot orange vapor success quality silk rabbit fan model radar"),
            "SR2mVQL31ykjzCmC83hHY2fbpcVU2CZq6U",
            100000000,
            "Crypto Web Payment",
            2,
            100000000,
            2,
            63,
        ).expect("sign");
        // println!("{:#?}", transaction);
        // assert_eq!(sig_hex.len(), 128);
    }

    #[test]
    fn second_signature_registration_schnorr() {
        let tx = build_second_signature_registration(
            "doll maple globe organ raccoon common only pause neglect athlete prize hurry",
            "youth soda robot orange vapor success quality silk rabbit fan model radar",
            2,
            2,
            63,
        ).expect("build");

        assert_eq!(tx.type_id as u8, 1);
        assert_eq!(tx.amount, 0);
        assert_eq!(tx.signature.len(), 128);

        match tx.asset {
            crate::enums::assets::Asset::Signature { ref public_key } => {
                assert!(!public_key.is_empty());
            }
            _ => panic!("Expected Signature asset"),
        }

        assert!(tx.verify());
    }
}
