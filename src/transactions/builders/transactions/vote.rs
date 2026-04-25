use anyhow;

use crate::configuration::fees;
use crate::enums::{TransactionGroup, TransactionType};
use crate::enums::assets::Asset;
use crate::transactions::transaction::Transaction;
use crate::utils::slot;

pub fn build_vote(
    passphrase: &str,
    second_passphrase: Option<&str>,
    votes: Vec<String>,
    nonce: u64,
    version: u8,
    network: u8,
) -> Result<Transaction, anyhow::Error> {

    let mut transaction = Transaction::default();

    transaction.type_id = TransactionType::Vote;
    transaction.type_group = TransactionGroup::Core as u32;

    transaction.asset = Asset::Votes(votes);

    transaction.amount = 0;
    transaction.fee = fees::get(TransactionType::Vote).unwrap();

    transaction.nonce = nonce;
    transaction.version = version;
    transaction.network = network;
    transaction.timestamp = slot::get_time();

    // recipient MUST be empty (important)
    transaction.recipient_id = String::new();

    transaction.hash(passphrase)?;
    transaction.id = transaction.get_id()?;

    transaction = transaction.sign_schnorr(passphrase)?;

    if let Some(pass) = second_passphrase {
        transaction = transaction.second_sign_schnorr(pass)?;
    }

    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn vote_schnorr() {
        let votes = vec![
            "+03b12f993c9b0c6b7d6b5d4c2a3f8f2d8d4a7b6c5e4f3a2b1c0d9e8f7a6b5c4d3".to_string()
        ];

        let tx = build_vote(
            "doll maple globe organ raccoon common only pause neglect athlete prize hurry",
            Some("youth soda robot orange vapor success quality silk rabbit fan model radar"),
            votes,
            2,
            2,
            63,
        ).expect("vote build");

        assert_eq!(tx.type_id as u8, 3);
        assert_eq!(tx.amount, 0);
        assert!(tx.signature.len() == 128);
        assert!(tx.second_signature.is_some());

        assert!(tx.verify());
    }
}
