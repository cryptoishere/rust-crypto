use crate::identities::private_key::PrivateKey;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SerializableKeypair {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "privateKey")]
    pub private_key: String,
    #[serde(rename = "compressed")]
    pub compressed: bool,
}

impl SerializableKeypair {
    pub fn from_keys(public_key: &secp256k1::PublicKey, secret_key: &PrivateKey) -> Self {
        Self {
            public_key: hex::encode(public_key.serialize()), // compressed format
            private_key: hex::encode(secret_key.secret_bytes()),
            compressed: true,
        }
    }
}