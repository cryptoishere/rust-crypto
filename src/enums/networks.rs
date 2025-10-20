#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Network {
    Mainnet,
    Devnet,
    Testnet,
}

impl Network {
    pub fn epoch(&self) -> &'static str {
        match *self {
            Network::Mainnet => "2023-08-29T00:00:00.000Z",
            Network::Devnet => "2023-04-21T03:36:39.887Z",
            Network::Testnet => "2023-07-21T00:00:00.000Z",
        }
    }

    pub fn version(&self) -> u8 {
        match *self {
            Network::Mainnet => 0x3F,
            Network::Devnet => 0x40,
            Network::Testnet => 0x41,
        }
    }

    pub fn wif(&self) -> u8 {
        match *self {
            Network::Mainnet => 255,
            Network::Devnet => 85,
            Network::Testnet => 68,
        }
    }
}
