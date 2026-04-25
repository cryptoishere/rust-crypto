use std::sync::OnceLock;

use crate::enums::networks::Network;

lazy_static! {
    static ref NETWORK: OnceLock<Network> = OnceLock::new();
}

pub fn set(network: Network) {
    match NETWORK.set(network) {
        Ok(_) => log::debug!("Network initialized."),
        Err(_e) => {}
    };
}

pub fn get() -> Network {
    NETWORK.get_or_init(|| Network::Devnet).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_network() {
        assert_eq!(get(), Network::Devnet);
    }

    #[ignore]
    #[test]
    fn set_network() {
        set(Network::Devnet);
        assert_eq!(get(), Network::Devnet);
    }
}
