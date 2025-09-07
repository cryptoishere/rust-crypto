use anyhow::{Result, anyhow};
use hex;
use secp256k1::PublicKey;

use crate::identities::private_key::PrivateKey;

use super::super::SECP256K1;
use super::private_key;

pub fn from_passphrase(passphrase: &str) -> Result<PublicKey> {
    let private_key = private_key::from_passphrase(passphrase.as_bytes())
        .map_err(|e| anyhow!("Secp256k1 error: {}", e))?;

    Ok(from_private_key(&private_key))
}

pub fn from_hex(public_key: &str) -> Result<PublicKey> {
    let pubkey_hash = hex::decode(public_key)
        .map_err(|e| anyhow!("hex error: {}", e))?;

    Ok(PublicKey::from_slice(pubkey_hash.as_slice())
        .map_err(|e| anyhow!("Secp256k1 error: {}", e))?)
}

pub fn from_private_key(private_key: &PrivateKey) -> PublicKey {
    PublicKey::from_secret_key(&SECP256K1, private_key)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn public_key_from_passphrase() {
        let public_key = from_passphrase("this is a top secret passphrase").unwrap();
        assert_eq!(
            public_key.to_string(),
            "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"
        );
    }

    #[test]
    fn public_key_from_hex() {
        let public_key =
            from_hex("034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192");
        assert!(public_key.is_ok());
        assert_eq!(
            public_key.unwrap().to_string(),
            "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"
        );
    }
}
