use bs58;
use sha2::{Digest, Sha256};

use super::super::configuration;

pub fn from_passphrase(passphrase: &str) -> String {
    let mut bytes = vec![];
    bytes.push(configuration::network::get().wif());

    bytes.extend_from_slice(&Sha256::digest(&passphrase.as_bytes()));
    bytes.push(0x01);

    bs58::encode(&bytes)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .with_check()
        .into_string()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn wif_from_passphrase() {
        assert_eq!(
            from_passphrase("this is a top secret passphrase"),
            "SGq4xLgZKCGxs7bjmwnBrWcT4C1ADFEermj846KC97FSv1WFD1dA"
        );
    }
}
