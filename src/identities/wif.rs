use bs58;

use super::super::configuration;
use super::private_key;

pub fn from_passphrase(passphrase: &str) -> String {
    let mut bytes = vec![];

    bytes.push(configuration::network::get().wif());

    let secret_key = private_key::from_passphrase(passphrase.as_bytes())
        .expect("valid secret key");

    bytes.extend_from_slice(&secret_key.secret_bytes());

    bytes.push(0x01); // compressed flag

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
            "DhYUMd46S8QH38USmWEHBia3uFviFgBs2Dn3VUs9QSBwysdcYs54"
        );
    }
}
