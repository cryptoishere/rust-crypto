use anyhow::anyhow;
use hex;
use secp256k1::{Error, Message, SecretKey};
use sha2::{Digest, Sha256};

use crate::identities::schnorr::schnorrleg_sign;

use super::super::SECP256K1;

pub fn from_passphrase(passphrase: &[u8]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(&Sha256::digest(passphrase)[..])
}

pub fn from_hex(private_key: &str) -> Result<SecretKey, Error> {
    SecretKey::from_slice(hex::decode(private_key)
        .map_err(|_| Error::InvalidSecretKey)?.as_slice())
}

pub fn sign(bytes: &[u8], passphrase: &str) -> Result<String, Error> {
    let key = from_passphrase(passphrase.as_bytes())?;

    let hash = Sha256::digest(bytes); // [u8; 32]
    let msg = Message::from_digest(hash.into());

    let sig = SECP256K1.sign_ecdsa(&msg, &key);

    Ok(hex::encode(sig.serialize_der()))
}

pub fn sign_schnorr_bcrypto_legacy(tx_hash: &[u8], passphrase: &str) -> anyhow::Result<String> {
    let secret_key = from_passphrase(passphrase.as_bytes()).map_err(|_| anyhow!("failed convert to bytes"))?;
    let tx_hash_32: [u8; 32] = tx_hash.try_into().map_err(|_| anyhow!("tx_hash must be 32 bytes"))?;

    let sig = schnorrleg_sign(&tx_hash_32, &secret_key)?;

    Ok(hex::encode(sig))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn smoke_sign() {
        let msg = [0u8;32];
        let pass = "test-passphrase";
        let sig_hex = sign_schnorr_bcrypto_legacy(&msg, pass).expect("sign");
        assert_eq!(sig_hex.len(), 128);
    }

    #[test]
    fn private_key_from_passphrase() {
        let private_key = from_passphrase("this is a top secret passphrase".as_bytes()).unwrap();
        assert_eq!(
            private_key.display_secret().to_string(),
            "d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712"
        );
    }

    #[test]
    fn private_key_from_hex() {
        let private_key =
            from_hex("d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712");
        assert!(private_key.is_ok());
        assert_eq!(
            private_key.unwrap().display_secret().to_string(),
            "d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712"
        );
    }
}
