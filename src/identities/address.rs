use bs58;
use hex;
use secp256k1::PublicKey;
use ripemd::{Ripemd160, Digest};

use crate::identities::private_key::PrivateKey;

use super::super::configuration;
use super::private_key;
use super::public_key;

pub fn from_passphrase(passphrase: &str, network_version: Option<u8>) -> String {
    let private_key = private_key::from_passphrase(passphrase);
    from_private_key(&private_key, network_version)
}

fn from_private_key(private_key: &PrivateKey, network_version: Option<u8>) -> String {
    let public_key = public_key::from_private_key(private_key);
    from_public_key(&public_key, network_version)
}

pub fn from_public_key(public_key: &PublicKey, network_version: Option<u8>) -> String {
    let network_version = match network_version {
        Some(network_version) => network_version,
        None => configuration::network::get().version(),
    };

    // TODO: fix unwrap
    let bytes = hex::decode(public_key.to_string()).unwrap();

    let ripemd160 = Ripemd160::digest(&bytes);
    let mut data = vec![];
    data.push(network_version);
    data.extend_from_slice(&ripemd160);
    bs58::encode(&data)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .with_check()
        .into_string()
}

pub fn validate(address: &str, network_version: Option<u8>) -> bool {
    let network_version = match network_version {
        Some(network_version) => network_version,
        None => configuration::network::get().version(),
    };

    let bytes = bs58::decode(address)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .with_check(None)
        .into_vec();
    if let Ok(value) = bytes {
        return *value.first().unwrap() == network_version;
    }

    false
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::enums::Network;

    #[test]
    #[ignore]
    fn address_from_passphrase() {
        let private_key = from_passphrase(
            "this is a top secret passphrase",
            Some(Network::Devnet.version()),
        );
        assert_eq!(
            private_key.to_string(),
            "D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib"
        );
    }

    #[test]
    fn private_key_from_hex() {
        //    let private_key = from_hex("d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712");
        //        assert!(private_key.is_ok());
        //        assert_eq!(private_key.unwrap().to_string(), "d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712");
    }
}
