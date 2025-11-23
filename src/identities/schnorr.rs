// schnorr_bcrypto_legacy.rs
use anyhow::anyhow;
use lazy_static::lazy_static;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Digest, Sha256};
use crypto_bigint::{U256, U512, NonZero, Encoding};
use std::convert::TryInto;

lazy_static! {
    static ref N_RAW: [u8; 32] = [
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
    ];
    static ref N: U256 = U256::from_be_bytes(*N_RAW);
    static ref NZ: NonZero<U256> = NonZero::new(*N).expect("n must be nonzero");
    static ref P_RAW: [u8; 32] = [
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,
    ];
    static ref P: U256 = U256::from_be_bytes(*P_RAW);
}

fn u256_to_u512(x: &U256) -> U512 {
    let mut buf = [0u8; 64];
    buf[32..64].copy_from_slice(&x.to_be_bytes());
    U512::from_be_bytes(buf)
}

fn hash_nonce(seckey: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seckey);
    hasher.update(msg);
    hasher.finalize().into()
}

fn hash_challenge(R_x: &[u8; 32], A_comp: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(R_x);
    hasher.update(A_comp);
    hasher.update(msg);
    hasher.finalize().into()
}

fn mul_mod_n(a: &U256, b: &U256) -> U256 {
    let wide = u256_to_u512(a) * u256_to_u512(b);
    let reduced = wide % u256_to_u512(&N);
    let bytes: [u8; 64] = reduced.to_be_bytes();
    U256::from_be_bytes(bytes[32..64].try_into().unwrap())
}

fn add_mod_n(a: &U256, b: &U256) -> U256 {
    let wide = u256_to_u512(a) + u256_to_u512(b);
    let reduced = wide % u256_to_u512(&N);
    let bytes: [u8; 64] = reduced.to_be_bytes();
    U256::from_be_bytes(bytes[32..64].try_into().unwrap())
}

fn mod_pow_u256(base: &U256, exp: &U256, modulus: &U256) -> U256 {
    let mut result = U256::ONE; // start with 1
    let mut base_curr = *base;
    let mut exp_copy = *exp;

    for _ in 0..256 {
        // check least significant bit
        if (exp_copy & U256::from_be_bytes([0u8;31].iter().chain(&[1u8]).cloned().collect::<Vec<_>>().try_into().unwrap())) != U256::ZERO {
            let wide = u256_to_u512(&result) * u256_to_u512(&base_curr);
            let reduced = wide % u256_to_u512(modulus);
            let bytes: [u8; 64] = reduced.to_be_bytes();
            result = U256::from_be_bytes(bytes[32..64].try_into().unwrap());
        }

        // square base_curr
        let wide_b = u256_to_u512(&base_curr) * u256_to_u512(&base_curr);
        let reduced_b = wide_b % u256_to_u512(modulus);
        let bytes_b: [u8; 64] = reduced_b.to_be_bytes();
        base_curr = U256::from_be_bytes(bytes_b[32..64].try_into().unwrap());

        // shift exponent right by 1
        let mut eb = exp_copy.to_be_bytes();
        let mut carry = 0u8;
        for i in 0..32 {
            let byte = eb[i];
            let new_carry = (byte & 1) << 7;
            eb[i] = (byte >> 1) | carry;
            carry = new_carry;
        }
        exp_copy = U256::from_be_bytes(eb);
    }

    result
}

fn is_quad_y_bytes(y_bytes: &[u8; 32]) -> Result<bool, anyhow::Error> {
    let y = U256::from_be_bytes(*y_bytes);
    let mut p_minus_1 = *P;
    // subtract 1
    let mut b = P.to_be_bytes();
    for i in (0..32).rev() {
        if b[i] == 0 { b[i] = 0xFF; } else { b[i] -= 1; break; }
    }
    p_minus_1 = U256::from_be_bytes(b);
    // divide by 2
    let mut b = p_minus_1.to_be_bytes();
    let mut carry = 0u8;
    for i in 0..32 {
        let byte = b[i];
        let new_carry = (byte & 1) << 7;
        b[i] = (byte >> 1) | carry;
        carry = new_carry;
    }
    let exp = U256::from_be_bytes(b);
    let r = mod_pow_u256(&y, &exp, &P);
    let mut one = [0u8; 32]; one[31] = 1;
    Ok(r == U256::from_be_bytes(one))
}

fn u256_from_32_bytes_reduced(b: &[u8; 32]) -> U256 {
    let x = U256::from_be_bytes(*b);
    let wide = u256_to_u512(&x);
    let reduced = wide % u256_to_u512(&N);
    let bytes: [u8; 64] = reduced.to_be_bytes();
    U256::from_be_bytes(bytes[32..64].try_into().unwrap())
}

pub fn schnorrleg_sign(msg: &[u8; 32], seckey: &SecretKey) -> anyhow::Result<[u8; 64]> {
    let secp = Secp256k1::new();
    let sk_bytes: [u8; 32] = seckey.secret_bytes();
    let pk = PublicKey::from_secret_key(&secp, seckey);
    let A_comp = pk.serialize();
    let k_raw_bytes = hash_nonce(&sk_bytes, msg);
    let mut k = u256_from_32_bytes_reduced(&k_raw_bytes);
    if k == U256::from_be_bytes([0u8;32]) { return Err(anyhow!("k==0")); }

    let mut k_bytes = k.to_be_bytes();
    let mut R_sk = SecretKey::from_slice(&k_bytes).unwrap();
    let mut R = PublicKey::from_secret_key(&secp, &R_sk);
    let mut R_ser = R.serialize();
    let mut R_x = [0u8; 32]; R_x.copy_from_slice(&R_ser[1..33]);
    let R_un = R.serialize_uncompressed();
    let mut R_y = [0u8;32]; R_y.copy_from_slice(&R_un[33..65]);
    if !is_quad_y_bytes(&R_y)? {
        let mut n_minus_k_bytes = N.to_be_bytes();
        let mut k_bytes = k.to_be_bytes();
        let mut res = [0u8;32]; let mut borrow = 0u16;
        for i in (0..32).rev() {
            let nb = n_minus_k_bytes[i] as i16;
            let kb = k_bytes[i] as i16;
            let mut v = nb - kb - borrow as i16;
            if v < 0 { v += 256; borrow = 1; } else { borrow = 0; }
            res[i] = v as u8;
        }
        k = U256::from_be_bytes(res) % *N;
        if k == U256::from_be_bytes([0u8;32]) { return Err(anyhow!("k==0 after flip")); }
        k_bytes = k.to_be_bytes();
        R_sk = SecretKey::from_slice(&k_bytes).unwrap();
        R = PublicKey::from_secret_key(&secp, &R_sk);
        R_ser = R.serialize();
        R_x.copy_from_slice(&R_ser[1..33]);
    }

    let e_raw = hash_challenge(&R_x, &A_comp, msg);
    let e = u256_from_32_bytes_reduced(&e_raw);
    let d = u256_from_32_bytes_reduced(&sk_bytes);
    let ed = mul_mod_n(&e, &d);
    let s = add_mod_n(&k, &ed);
    if s == U256::from_be_bytes([0u8;32]) { return Err(anyhow!("s==0")); }

    let mut sig = [0u8;64];
    sig[..32].copy_from_slice(&R_x);
    sig[32..].copy_from_slice(&s.to_be_bytes());
    Ok(sig)
}
