use std::collections::HashMap;
use std::sync::OnceLock;

use crate::enums::TransactionType;

lazy_static! {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    static ref FEES: OnceLock<HashMap<TransactionType, u64>> = {
        let mut m = HashMap::with_capacity(11);
        m.insert(TransactionType::Transfer, TransactionType::Transfer.fee());
        m.insert(TransactionType::SecondSignature, TransactionType::SecondSignature.fee());
        m.insert(TransactionType::DelegateRegistration, TransactionType::DelegateRegistration.fee());
        m.insert(TransactionType::Vote, TransactionType::Vote.fee());
        m.insert(TransactionType::MultiSignature, TransactionType::MultiSignature.fee());
        m.insert(TransactionType::Ipfs, TransactionType::Ipfs.fee());
        m.insert(TransactionType::MultiPayment, TransactionType::MultiPayment.fee());
        m.insert(TransactionType::DelegateResignation, TransactionType::DelegateResignation.fee());
        m.insert(TransactionType::HtlcLock, TransactionType::HtlcLock.fee());
        m.insert(TransactionType::HtlcClaim, TransactionType::HtlcClaim.fee());
        m.insert(TransactionType::HtlcRefund, TransactionType::HtlcRefund.fee());

        let lock = OnceLock::new();
        lock.set(m).expect("Must not exist on first initialization");
        lock
    };
}

pub fn get(transaction_type: TransactionType) -> Option<u64> {
    FEES.get()
        .expect("Must exists due to static initalization")
        .get(&transaction_type)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_fee() {
        assert_eq!(get(TransactionType::Vote).unwrap(), TransactionType::Vote.fee());
    }
}
