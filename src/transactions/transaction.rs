use anyhow::{anyhow};
use bs58;
use byteorder::{LittleEndian, WriteBytesExt};
use hex;
use secp256k1::Message;
use secp256k1::ecdsa::Signature;
use serde_json;
use sha2::{Digest, Sha256};
use std::iter;

use crate::components::identities::keypair::SerializableKeypair;
use crate::components::transaction::TransactionHash;
use crate::enums::assets::Asset;
use crate::enums::TransactionType;
use crate::identities::{private_key, public_key};
use crate::utils::ser::is_zero;

use super::super::SECP256K1;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(skip)]
    pub header: u8,
    pub version: u8,
    pub network: u8,
    #[serde(skip_serializing_if = "is_zero")]
    pub type_group: u32,
    #[serde(rename = "type")]
    pub type_id: TransactionType,
    pub nonce: u64,
    #[serde(skip)]
    pub timelock_type: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
    pub sender_public_key: String,
    pub fee: u64,
    pub amount: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vendor_field: String,
    #[serde(skip_serializing_if = "Asset::is_none")]
    pub asset: Asset,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub recipient_id: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_signature: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sign_signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(skip)]
    pub vendor_field_hex: String,
    #[serde(skip)]
    pub expiration: u32,
    #[serde(skip)]
    pub timestamp: u32,
    #[serde(skip)]
    pub timelock: u64,
    #[serde(skip)]
    pub hash: TransactionHash,
    #[serde(skip)]
    pub keys: SerializableKeypair,
    pub id: String,
}

impl Transaction {
    pub fn get_id(&self) -> anyhow::Result<String> {
        let bytes = self.to_bytes(false, false, false)?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    pub fn sign(&mut self, passphrase: &str) -> &Self {
        let private_key = private_key::from_passphrase(passphrase.as_bytes()).expect("Unable to get Secret Key");
        let public_key = public_key::from_private_key(&private_key);
        self.sender_public_key = public_key.to_string();
        self.signature = private_key::sign(&self.to_bytes(true, true, false).unwrap(), passphrase).expect("Unable to sign");
        self
    }

    pub fn second_sign(&mut self, passphrase: &str) -> &Self {
        self.sign_signature = private_key::sign(&self.to_bytes(false, true, false).unwrap(), passphrase).expect("Unable to sign");
        self
    }

    pub fn verify(&self) -> bool {
        self.internal_verify(
            &self.sender_public_key,
            &self.signature,
            &self.to_bytes(true, true, false).unwrap(),
        )
    }

    pub fn second_verify(&self, sender_public_key: &str) -> bool {
        self.internal_verify(
            &sender_public_key,
            &self.sign_signature,
            &self.to_bytes(false, true, false).unwrap(),
        )
    }

    fn to_bytes(&self, skip_signature: bool, skip_second_signature: bool, is_second_signature: bool) -> anyhow::Result<Vec<u8>> {
        let mut buffer = vec![];

        buffer.write_u8(0xFF)?;

        buffer.write_u8(self.version as u8)?;
        buffer.write_u8(self.network as u8)?;
        buffer.write_u32::<LittleEndian>(self.type_group)?;
        buffer.write_u16::<LittleEndian>(self.type_id as u16)?;

        buffer.write_u64::<LittleEndian>(self.nonce)?;

        if !is_second_signature {
            buffer.extend_from_slice(&hex::decode(&self.sender_public_key)?);
        }

        buffer.write_u64::<LittleEndian>(self.fee)?;

        if self.vendor_field.is_empty() {
            buffer.write_u8(0x00)?;
        } else {
            let vendor_bytes = self.vendor_field.as_bytes();
            buffer.write_u8(vendor_bytes.len() as u8)?;
            buffer.extend_from_slice(vendor_bytes);
        }

        match self.type_id {
            TransactionType::Transfer => {
                buffer.write_u64::<LittleEndian>(self.amount)?;

                buffer.write_u32::<LittleEndian>(self.expiration)?;

                let skip_recipient_id = self.type_id == TransactionType::SecondSignatureRegistration
                    || self.type_id == TransactionType::MultiSignatureRegistration;

                let recipient_id = if !self.recipient_id.is_empty() && !skip_recipient_id {
                    bs58::decode(&self.recipient_id)
                        .with_alphabet(bs58::Alphabet::BITCOIN)
                        .with_check(None)
                        .into_vec()?
                } else {
                    iter::repeat(0).take(21).collect()
                };

                assert_eq!(recipient_id.len(), 21, "Check length");

                buffer.extend_from_slice(&recipient_id);
            }
            _ => {}
        }

        // Payload
        let payload: Vec<u8> = match self.asset {
            Asset::Signature { ref public_key } => hex::decode(&public_key)?,
            Asset::Delegate { ref username } => username.to_owned().as_bytes().to_vec(),
            Asset::Votes(ref votes) => votes.join("").as_bytes().to_vec(),
            Asset::MultiSignatureRegistration {
                min,
                lifetime,
                ref keysgroup,
            } => {
                let mut buffer = vec![];
                buffer.push(min);
                buffer.push(lifetime);
                buffer.extend_from_slice(keysgroup.clone().join("").as_bytes());

                buffer
            }
            _ => vec![],
        };

        buffer.extend_from_slice(&payload);

        // Signature
        if !skip_signature && !self.signature.is_empty() {
            buffer.extend_from_slice(&hex::decode(&self.signature)?);
        }

        // Second Signature
        if !skip_second_signature && !self.second_signature.is_none() {
            buffer.extend_from_slice(&hex::decode(self.second_signature.as_ref().expect("Safe here"))?);
        }

        Ok(buffer)
    }

    fn internal_verify(&self, sender_public_key: &str, signature: &str, hash_bytes: &[u8]) -> bool {
        let hash = Sha256::digest(&hash_bytes);
        let msg = Message::from_digest_slice(&hash).unwrap();

        let sig = Signature::from_der(&hex::decode(signature).unwrap()).unwrap();
        let pk = public_key::from_hex(&sender_public_key).unwrap();
        SECP256K1.verify_ecdsa(&msg, &sig, &pk).is_ok()
    }

    pub(crate) fn hash(&mut self, passphrase: &str) -> anyhow::Result<&Self> {
        let private_key = private_key::from_passphrase(passphrase.as_bytes())
            .map_err(|e| anyhow!("Secp256k1 error: {}", e))?;

        let public_key = public_key::from_private_key(&private_key);
        self.sender_public_key = public_key.to_string();

        let msg = self.hash_message(true, true, false)?;
        self.hash = TransactionHash { hash: *msg.as_ref()};

        Ok(self)
    }

    // Compute SHA256 hash of the input message
    fn hash_message(&mut self, skip_signature: bool, skip_second_signature: bool, is_second_signature: bool) -> anyhow::Result<Message> {
        let hash = Sha256::digest(self.to_bytes(skip_signature, skip_second_signature, is_second_signature)?); // [u8; 32]
        Ok(Message::from_digest(hash.into()))
    }

    pub(crate) fn sign_schnorr(mut self, passphrase: &str) -> anyhow::Result<Self> {
        self.signature = private_key::sign_schnorr_bcrypto_legacy(&self.hash.hash, passphrase)?;

        Ok(self)
    }

    pub(crate) fn second_sign_schnorr(mut self, passphrase: &str) -> anyhow::Result<Self> {
        let msg = self.hash_message(true, true, true)?;

        self.second_signature = Some(private_key::sign_schnorr_bcrypto_legacy(msg.as_ref(), passphrase)?);

        Ok(self)
    }

    pub fn to_params(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}
