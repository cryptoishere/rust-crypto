use std::convert::Infallible;
use anyhow::anyhow;
use hex;
use secp256k1::{Error, Keypair, Message, PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256};
use crypto_bigint::{Encoding, NonZero, U256, U512, Zero, DecodeError};

use super::super::SECP256K1;

pub type PrivateKey = SecretKey;

pub fn from_passphrase(passphrase: &[u8]) -> Result<PrivateKey, Error> {
    PrivateKey::from_slice(&Sha256::digest(passphrase)[..])
}

pub fn from_hex(private_key: &str) -> Result<PrivateKey, Error> {
    PrivateKey::from_slice(hex::decode(private_key)
        .map_err(|_| Error::InvalidSecretKey)?.as_slice())
}

pub fn sign(bytes: &[u8], passphrase: &str) -> Result<String, Error> {
    let key = from_passphrase(passphrase.as_bytes())?;

    let hash = Sha256::digest(bytes); // [u8; 32]
    let msg = Message::from_digest(hash.into());

    let sig = SECP256K1.sign_ecdsa(&msg, &key);

    Ok(hex::encode(sig.serialize_der()))
}

pub fn hash(bytes: &[u8], passphrase: &[u8]) -> Result<(Message, Keypair), Error> {
    let key = from_passphrase(passphrase)?;
    let keypair = Keypair::from_secret_key(&SECP256K1, &key);

    // Compute SHA256 hash of the input message
    let hash = Sha256::digest(bytes); // [u8; 32]
    let msg = Message::from_digest(hash.into());

    Ok((msg, keypair))
}

/// secp256k1 curve order n
const N_RAW: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

lazy_static::lazy_static! {
    static ref N: U256 = U256::from_be_bytes(N_RAW);
    static ref NZ: NonZero<U256> = NonZero::new(*N).expect("Must be NonZero value");
}

/// Hash nonce like bcrypto legacy: H(seckey || msg)
fn hash_nonce(msg: &[u8], seckey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seckey);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Hash challenge like bcrypto legacy: H(R || A || msg)
fn hash_challenge(R_bytes: &[u8; 32], A_bytes: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(R_bytes);
    hasher.update(A_bytes);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Convert 32-byte array to U256 modulo n (rejects zero)
fn to_scalar(bytes: &[u8; 32]) -> Result<U256, DecodeError> {
    let scalar = U256::from_be_slice(bytes) % *N;
    if !bool::from(scalar.is_zero()) {
        return Err(DecodeError::InvalidDigit);
    }

    Ok(scalar)
}

/// (a * b) mod n
fn mul_mod_n(a: &U256, b: &U256) -> Result<U256, Infallible> {
    let wide = U512::from(a) * U512::from(b);
    let n_wide = U512::from(&*N); // Convert U256 -> U512 via reference
    let reduced = wide % n_wide;
    U256::try_from(&reduced)
}

/// (a + b) mod n
fn add_mod_n(a: &U256, b: &U256) -> U256 {
    (a.wrapping_add(b)) % *N
}

/// https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki#user-content-Specification
/// Schnorr legacy signature (bcrypto-compatible):
/// - Nonce = H(seckey || msg)
/// - Challenge = H(R_x || A_compressed || msg)
/// - Aux randomness = zero
fn schnorrleg_sign(tx_hash: &[u8], seckey: &PrivateKey) -> anyhow::Result<[u8; 64]> {
    let sk_bytes = seckey.secret_bytes();

    // Compressed pubkey A (33 bytes)
    let A = PublicKey::from_secret_key(&SECP256K1, seckey);
    let A_bytes = A.serialize(); // 33 bytes

    // k = H(seckey || tx_hash) mod n
    let mut k = to_scalar(&hash_nonce(tx_hash, &sk_bytes))
        .map_err(|e| anyhow!("Error: {e}"))?;

    // R = k * G
    let R_sk = PrivateKey::from_slice(&k.to_be_bytes()).map_err(|e| anyhow!("Error: {e}"))?;
    let R = PublicKey::from_secret_key(&SECP256K1, &R_sk);
    let R_ser = R.serialize(); // 33 bytes
    let mut R_x = [0u8; 32];
    R_x.copy_from_slice(&R_ser[1..33]);

    // If y(R) odd, negate k
    if R_ser[0] == 0x03 {
        k = (*N).wrapping_sub(&k) % *N;
    }

    // e = H(R_x || A_compressed || tx_hash) mod n
    let e = to_scalar(&hash_challenge(&R_x, &A_bytes, tx_hash)).map_err(|e| anyhow!("Error: {e}"))?;

    // s = k + e*d mod n
    let d = to_scalar(&sk_bytes).map_err(|e| anyhow!("Error: {e}"))?;
    let ed = mul_mod_n(&e, &d).map_err(|e| anyhow!("Error: {e}"))?;
    let s = add_mod_n(&k, &ed);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&R_x);
    sig[32..].copy_from_slice(&s.to_be_bytes());
    Ok(sig)
}

pub fn sign_schnorr_bcrypto_legacy(tx_hash: &[u8], passphrase: &str) -> anyhow::Result<String> {
    let priv_key_bytes = Sha256::digest(passphrase.as_bytes());
    let secret_key = PrivateKey::from_slice(&priv_key_bytes).map_err(|e| anyhow!("Error: {e}"))?;
    let sig = schnorrleg_sign(tx_hash, &secret_key).map_err(|e| anyhow!("Error: {e}"))?;
    Ok(hex::encode(sig))
}

pub fn schnorrleg_verify(msg: &[u8], sig: &[u8; 64], pubkey: &PublicKey) -> anyhow::Result<bool> {
    // Split signature into R_x and s
    let mut R_x = [0u8; 32];
    R_x.copy_from_slice(&sig[..32]);
    let s_bytes = &sig[32..];
    let s = to_scalar(&s_bytes.try_into()?)?;

    // A_compressed (33 bytes)
    let A_bytes = pubkey.serialize();

    // e = H(R_x || A_compressed || msg) mod n
    let e = to_scalar(&hash_challenge(&R_x, &A_bytes, msg)).map_err(|e| anyhow!("Error: {e}"))?;

    // s*G
    let s_sk = SecretKey::from_slice(&s.to_be_bytes()).map_err(|e| anyhow!("Error: {e}"))?;
    let sG = PublicKey::from_secret_key(&SECP256K1, &s_sk);

    // Compute (-e)*A using tweak bytes
    let neg_e = (*N).wrapping_sub(&e) % *N;
    let neg_e_bytes = neg_e.to_be_bytes(); // [u8;32]
    let scalar = Scalar::from_be_bytes(neg_e_bytes).map_err(|e| anyhow!("Secp256k1 error: {}", e))?;
    let neg_eA = pubkey.mul_tweak(&SECP256K1, &scalar).map_err(|e| anyhow!("Secp256k1 error: {}", e))?;;

    // R' = s*G + (-e)*A
    let R_candidate = sG.combine(&neg_eA).map_err(|e| anyhow!("Secp256k1 error: {}", e))?;
    let R_ser = R_candidate.serialize(); // compressed (33 bytes)
    let R_x_check = &R_ser[1..33];

    // Verify x coordinate match AND even Y
    Ok(R_x_check == R_x && R_ser[0] == 0x02)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_schnorr_match_bcrypto() {
        let passphrase = "result manage security quarter sister accident recall finger kiwi clown mirror candy";
        let tx_bytes = vec![
            138, 157, 199, 67, 88, 165, 69, 67, 21, 238, 159, 255, 2, 103, 32, 99,
            138, 117, 90, 102, 1, 130, 107, 155, 165, 125, 206, 238, 219, 45, 207, 255,
        ];

        let sig_hex = sign_schnorr_bcrypto_legacy(&tx_bytes, passphrase).unwrap();
        println!("{}", sig_hex);
        assert_eq!(sig_hex, "2314dd6771ae8629a53b4c94ab7c451fc38e6a6832db77168d1cd05cd061585caa15dffb791be143c80d6387b7375fdd122dfaca16570bed65c2bf140c3e16fa");
    }

    #[test]
    fn test_schnorr_legacy_sign_verify() {
        let passphrase = "result manage security quarter sister accident recall finger kiwi clown mirror candy";
        let tx_bytes = vec![
            138, 157, 199, 67, 88, 165, 69, 67, 21, 238, 159, 255, 2, 103, 32, 99,
            138, 117, 90, 102, 1, 130, 107, 155, 165, 125, 206, 238, 219, 45, 207, 255,
        ];

        // Derive secret key and public key
        let sk = from_passphrase(passphrase.as_bytes()).unwrap();
        let pk = PublicKey::from_secret_key(&SECP256K1, &sk);

        // Sign using bcrypto legacy Schnorr
        let sig_hex = sign_schnorr_bcrypto_legacy(&tx_bytes, passphrase).unwrap();

        let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();

        // Verify the signature
        assert!(schnorrleg_verify(&tx_bytes, &sig_bytes, &pk).unwrap());
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
