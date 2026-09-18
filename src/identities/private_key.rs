use anyhow::anyhow;
use hex;
use secp256k1::{Error, SecretKey};
use sha2::{Digest, Sha256};

use crate::transactions::schnorr::sign_schnorr_bcrypto_legacy;

pub fn from_passphrase(passphrase: &[u8]) -> Result<SecretKey, Error> {
    let digest = Sha256::digest(passphrase);
    let bytes: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidSecretKey)?;
    SecretKey::from_secret_bytes(bytes)
}

pub fn from_hex(private_key: &str) -> Result<SecretKey, Error> {
    let decoded = hex::decode(private_key).map_err(|_| Error::InvalidSecretKey)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| Error::InvalidSecretKey)?;
    SecretKey::from_secret_bytes(bytes)
}

pub fn sign(tx_hash: &[u8], passphrase: &str) -> anyhow::Result<String> {
    let secret_key = from_passphrase(passphrase.as_bytes())
        .map_err(|_| anyhow!("failed convert to bytes"))?;
    let tx_hash_32: [u8; 32] = tx_hash
        .try_into()
        .map_err(|_| anyhow!("tx_hash must be 32 bytes"))?;

    let sig = sign_schnorr_bcrypto_legacy(&tx_hash_32, &secret_key)?;

    Ok(hex::encode(sig))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn smoke_sign() {
        let msg = [0u8; 32];
        let pass = "test-passphrase";
        let sig_hex = sign(&msg, pass).unwrap();
        assert_eq!(sig_hex.len(), 128);
    }

    #[test]
    fn private_key_from_passphrase() {
        let private_key = from_passphrase(b"this is a top secret passphrase").unwrap();
        assert_eq!(
            hex::encode(private_key.to_secret_bytes()),
            "d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712"
        );
    }

    #[test]
    fn private_key_from_hex() {
        let private_key =
            from_hex("d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712");
        assert!(private_key.is_ok());
        assert_eq!(
            hex::encode(private_key.unwrap().to_secret_bytes()),
            "d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712"
        );
    }
}
