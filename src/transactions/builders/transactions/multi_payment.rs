use anyhow;

use crate::configuration::fees;
use crate::enums::{TransactionGroup, TransactionType};
use crate::enums::assets::{Asset, Payment};
use crate::transactions::transaction::Transaction;
use crate::utils::slot;

pub fn build_multi_payment(
    passphrase: &str,
    second_passphrase: Option<&str>,
    payments: Vec<Payment>,
    nonce: u64,
    fee: Option<u64>,
    version: u8,
    network: u8,
) -> Result<Transaction, anyhow::Error> {
    if payments.len() < 2 {
        anyhow::bail!("Minimum 2 payments required");
    }

    if payments.len() > 256 {
        anyhow::bail!("Maximum 256 payments exceeded");
    }

    let mut transaction = Transaction::default();

    transaction.type_id = TransactionType::MultiPayment;
    transaction.type_group = TransactionGroup::Core as u32;

    transaction.asset = Asset::MultiPayment { payments };

    transaction.amount = 0;
    transaction.fee = fee.unwrap_or_else(|| fees::get(TransactionType::MultiPayment).unwrap());

    transaction.nonce = nonce;
    transaction.version = version;
    transaction.network = network;
    transaction.timestamp = slot::get_time();

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
    use crate::enums::assets::Payment;

    #[test]
    fn multi_payment_schnorr() {
        let payments = vec![
            Payment {
                amount: 50_000_000,
                recipient_id: "SR2mVQL31ykjzCmC83hHY2fbpcVU2CZq6U".to_string(),
            },
            Payment {
                amount: 25_000_000,
                recipient_id: "SR2mVQL31ykjzCmC83hHY2fbpcVU2CZq6U".to_string(),
            },
        ];

        let transaction = build_multi_payment(
            "doll maple globe organ raccoon common only pause neglect athlete prize hurry",
            Some("youth soda robot orange vapor success quality silk rabbit fan model radar"),
            payments,
            2,
            None,
            2,
            63,
        ).expect("sign");

        // println!("{:#?}", transaction);

        assert_eq!(transaction.type_id as u8, 6); // MultiPayment
        assert_eq!(transaction.amount, 0); // MUST be zero
        assert_eq!(transaction.version, 2);
        assert_eq!(transaction.network, 63);
        assert_eq!(transaction.nonce, 2);

        // signatures (Schnorr = 64 bytes = 128 hex chars)
        assert_eq!(transaction.signature.len(), 128);
        assert!(transaction.second_signature.is_some());
        assert_eq!(transaction.second_signature.as_ref().unwrap().len(), 128);

        match transaction.asset {
            crate::enums::assets::Asset::MultiPayment { ref payments } => {
                assert_eq!(payments.len(), 2);
                assert_eq!(payments[0].amount, 50_000_000);
                assert_eq!(payments[1].amount, 25_000_000);
            }
            _ => panic!("Expected MultiPayment asset"),
        }

        assert!(!transaction.id.is_empty());
        assert_eq!(transaction.id.len(), 64);

        assert!(transaction.verify());
    }
}
