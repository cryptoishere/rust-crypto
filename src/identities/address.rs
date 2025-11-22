use anyhow::{Result, anyhow};
use bs58;
use hex;
use secp256k1::PublicKey;
use ripemd::{Ripemd160, Digest};
use secp256k1::SecretKey;

use super::super::configuration;
use super::private_key;
use super::public_key;

pub fn from_passphrase(passphrase: &str, network_version: Option<u8>) -> Result<String> {
    let private_key = private_key::from_passphrase(passphrase.as_bytes())
        .map_err(|e| anyhow!("Secp256k1 error: {}", e))?;

    from_private_key(&private_key, network_version)
}

fn from_private_key(private_key: &SecretKey, network_version: Option<u8>) -> Result<String> {
    let public_key = public_key::from_private_key(private_key);
    from_public_key(&public_key, network_version)
}

pub fn from_public_key(public_key: &PublicKey, network_version: Option<u8>) -> Result<String> {
    let network_version = match network_version {
        Some(network_version) => network_version,
        None => configuration::network::get().version(),
    };

    let bytes = hex::decode(public_key.to_string())?;

    let ripemd160 = Ripemd160::digest(&bytes);
    let mut data = vec![];
    data.push(network_version);
    data.extend_from_slice(&ripemd160);
    Ok(bs58::encode(&data)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .with_check()
        .into_string())
}

pub fn validate(address: &str, network_version: Option<u8>) -> Result<bool> {
    let network_version = match network_version {
        Some(network_version) => network_version,
        None => configuration::network::get().version(),
    };

    let bytes = bs58::decode(address)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .with_check(None)
        .into_vec()?;

    match bytes.first() {
        Some(byte) => {
            Ok(*byte == network_version)
        }
        None => {
            Ok(false)
        }
    }
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
        ).unwrap();
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
