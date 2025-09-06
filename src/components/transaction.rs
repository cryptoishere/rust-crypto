#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransactionHash {
    pub hash: [u8; 32],
}
