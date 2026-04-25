enum_number!(TransactionType {
    Transfer = 0,
    SecondSignature = 1,
    DelegateRegistration = 2,
    Vote = 3,
    MultiSignature = 4,
    Ipfs = 5,
    MultiPayment = 6,
    DelegateResignation = 7,
    HtlcLock = 8,
    HtlcClaim = 9,
    HtlcRefund = 10,
});

impl TransactionType {
    pub fn fee(self) -> u64 {
        match self {
            TransactionType::Transfer => 10_000_000,
            TransactionType::SecondSignature => 1_500_000_000,
            TransactionType::DelegateRegistration => 2_500_000_000_000,
            TransactionType::Vote => 100_000_000,
            TransactionType::MultiSignature => 500_000_000,
            TransactionType::Ipfs => 0,
            TransactionType::MultiPayment => 60_000_000,
            TransactionType::DelegateResignation => 0,
            TransactionType::HtlcLock => 90_000_000,
            TransactionType::HtlcClaim => 0,
            TransactionType::HtlcRefund => 0,
        }
    }
}

impl Default for TransactionType {
    fn default() -> TransactionType {
        TransactionType::Transfer
    }
}

// impl From<u8> for TransactionType {
//     fn from(t: u8) -> TransactionType {
//         assert!(
//             TransactionType::Transfer as u8 <= t && t <= TransactionType::HtlcRefund as u8
//         );
//         unsafe { std::mem::transmute(t) }
//     }
// }

// If someone passes an invalid u8, you get UB. Since you already have a match in your serde visitor, a safer version is:
impl TryFrom<u8> for TransactionType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            0 => Ok(TransactionType::Transfer),
            1 => Ok(TransactionType::SecondSignature),
            2 => Ok(TransactionType::DelegateRegistration),
            3 => Ok(TransactionType::Vote),
            4 => Ok(TransactionType::MultiSignature),
            5 => Ok(TransactionType::Ipfs),
            6 => Ok(TransactionType::MultiPayment),
            7 => Ok(TransactionType::DelegateResignation),
            8 => Ok(TransactionType::HtlcLock),
            9 => Ok(TransactionType::HtlcClaim),
            10 => Ok(TransactionType::HtlcRefund),
            _ => Err(()),
        }
    }
}

impl From<TransactionType> for u8 {
    fn from(t: TransactionType) -> u8 {
        t as u8
    }
}
