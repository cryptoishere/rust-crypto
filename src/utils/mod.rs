use anyhow;
use hex;

mod macros;
pub(crate) mod slot;
pub(crate) mod ser;

pub fn str_from_hex(string: &str) -> Result<String, anyhow::Error> {
    Ok(String::from_utf8(hex::decode(string)?)?.to_string())
}

pub fn str_to_hex(string: &str) -> String {
    hex::encode(string.as_bytes())
}
