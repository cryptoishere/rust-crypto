use anyhow::{anyhow};
use bs58;
use byteorder::{LittleEndian, WriteBytesExt};
use hex;
use secp256k1::Message;
use serde_json;
use sha2::{Digest, Sha256};

use crate::enums::assets::Asset;
use crate::enums::{TypeGroup, TransactionType};
use crate::identities::{private_key, public_key};
use crate::utils::core::string_u64;

/// One block of the v3 second-signature section (`SPEC-PQ-V3.md` §4.3): `algorithm` 0 = secp256k1 Schnorr, 1 = ML-DSA-44.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PqSignatureBlock {
    pub algorithm: u8,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransactionHash {
    pub hash: [u8; 32],
}

fn default_type_group() -> u32 {
    TypeGroup::default()  as u32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub version: u8,
    pub network: u8,
    #[serde(default = "default_type_group")]
    pub type_group: u32,
    #[serde(rename = "type")]
    pub type_id: TransactionType,
    pub nonce: u64,
    pub sender_public_key: String,
    #[serde(with = "string_u64")]
    pub fee: u64,
    #[serde(default, with = "string_u64")]
    pub amount: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vendor_field: String,
    #[serde(skip)]
    pub expiration: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub recipient_id: String,
    #[serde(skip_serializing_if = "Asset::is_none")]
    pub asset: Asset,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_signature: Option<String>,
    /// Legacy v1 timestamp (absent on v2 transactions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    #[serde(skip)]
    pub hash: TransactionHash,
}

impl Transaction {
    pub fn get_id(&self) -> anyhow::Result<String> {
        let bytes = self.to_bytes(false, false)?;

        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    pub fn sign(&mut self, passphrase: &str) -> anyhow::Result<&Self> {
        let Ok(private_key) = private_key::from_passphrase(passphrase.as_bytes()) else {
            anyhow::bail!("Wrong passphrase");
        };

        let public_key = public_key::from_private_key(&private_key);
        self.sender_public_key = public_key.to_string();

        let ser_tx = self.to_bytes(true, true)?;

        self.signature = private_key::sign(
            &ser_tx,
            passphrase
        )?;

        Ok(self)
    }

    pub fn second_sign(&mut self, passphrase: &str) -> anyhow::Result<&Self> {
        let ser_tx = self.to_bytes(false, true)?;

        self.sign_signature = Some(private_key::sign(
            &ser_tx,
            passphrase
        )?);

        Ok(self)
    }

    pub fn verify(&self) -> anyhow::Result<bool> {
        let ser_tx = self.to_bytes(true, true)?;

        Ok(self.internal_verify(
            &self.sender_public_key,
            &self.signature,
            &ser_tx,
        ))
    }

    pub fn second_verify(&self, sender_public_key: &str) -> anyhow::Result<bool> {
        let ser_tx = self.to_bytes(false, true)?;

        Ok(self.internal_verify(
            &sender_public_key,
            &self.signature,
            &ser_tx,
        ))
    }

    // https://github.com/smartholdem/SHIPs/blob/master/SHIPS/SHIP-11.md
    fn to_bytes(&self, skip_signature: bool, skip_second_signature: bool) -> anyhow::Result<Vec<u8>> {
        let mut buffer = vec![];

        buffer.write_u8(0xFF)?;

        buffer.write_u8(self.version as u8)?;
        buffer.write_u8(self.network as u8)?;
        buffer.write_u32::<LittleEndian>(self.type_group)?;
        buffer.write_u16::<LittleEndian>(self.type_id as u16)?;

        buffer.write_u64::<LittleEndian>(self.nonce)?;

        buffer.extend_from_slice(&hex::decode(&self.sender_public_key)?);

        buffer.write_u64::<LittleEndian>(self.fee)?;

        if self.vendor_field.is_empty() {
            buffer.write_u8(0x00)?;
        } else {
            let vendor_bytes = self.vendor_field.as_bytes();
            if vendor_bytes.len() > 255 {
                anyhow::bail!("vendorField exceeds 255 bytes");
            }
            buffer.write_u8(vendor_bytes.len() as u8)?;
            buffer.extend_from_slice(vendor_bytes);
        }

        {
            // https://github.com/smartholdem/SHIPs/blob/master/SHIPS/SHIP-13.md

            if self.type_group != TypeGroup::Core as u32 {
                anyhow::bail!("unsupported typeGroup {}", self.type_group);
            }

            match self.type_id {
                TransactionType::Transfer => {
                    buffer.write_u64::<LittleEndian>(self.amount)?;
                    buffer.write_u32::<LittleEndian>(self.expiration)?;

                    let Ok(recipient_id) = bs58::decode(&self.recipient_id)
                            .with_alphabet(bs58::Alphabet::BITCOIN)
                            .with_check(None)
                            .into_vec() else {
                                anyhow::bail!("Failed to decode address");
                            };

                    buffer.extend_from_slice(&recipient_id);
                }
                TransactionType::SecondSignature => {
                    let Asset::Signature { ref public_key } = self.asset else {
                        anyhow::bail!("Second signature asset required");
                    };

                    // TODO: PQ
                    if false {

                    } else {
                        buffer.extend_from_slice(&hex::decode(public_key)?);
                    }
                }
                TransactionType::Vote => {
                    let Asset::Votes(ref votes) = self.asset else {
                        anyhow::bail!("Votes asset required");
                    };

                    buffer.write_u8(votes.len() as u8)?;

                    for vote in votes {
                        let (sign, pk) = vote
                            .split_at_checked(1)
                            .ok_or_else(|| anyhow::anyhow!(format!("bad vote {vote}")))?;

                        buffer.write_u8(if sign == "+" { 0x01 } else { 0x00 })?;

                        buffer.extend_from_slice(&hex::decode(pk)?);
                    }
                }
                // AIP11 type-specific serialization
                TransactionType::MultiPayment => {
                    self.serialize_multi_payment(&mut buffer)?;
                },
                _ => {}
            }
        }

        if !skip_signature {
            let Ok(sig_hex) = hex::decode(&self.signature) else {
                anyhow::bail!("Failed to decode transaction signature");
            };
    
            buffer.extend_from_slice(&sig_hex);
        }

        // TODO: PQ
        // https://github.com/smartholdem/SHIPs/blob/master/SHIPS/SHIP-19.md
        if false {

        }

        match (skip_second_signature, self.second_signature.as_ref()) {
            (false, Some(sig)) => {
                let Ok(sig_hex) = hex::decode(sig) else {
                    anyhow::bail!("Failed to decode transaction second signature");
                };

                buffer.extend_from_slice(&sig_hex);
            }
            _  => {}
        };

        Ok(buffer)
    }

    fn internal_verify(&self, sender_public_key: &str, signature: &str, hash_bytes: &[u8]) -> bool {
        let hash = Sha256::digest(hash_bytes);
        let msg: [u8; 32] = hash.into();

        let sig_bytes = match hex::decode(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let pk = match public_key::from_hex(sender_public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        if sig_bytes.len() == 64 {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&sig_bytes);

            return crate::transactions::schnorr::schnorrleg_verify(&msg, &sig, &pk)
                .unwrap_or(false);
        }

        false
    }

    pub(crate) fn hash(&mut self, passphrase: &str) -> anyhow::Result<&Self> {
        let private_key = private_key::from_passphrase(passphrase.as_bytes())
            .map_err(|e| anyhow!("Secp256k1 error: {}", e))?;

        let public_key = public_key::from_private_key(&private_key);
        self.sender_public_key = public_key.to_string();

        let msg = self.hash_message(true, true)?;
        self.hash = TransactionHash { hash: *msg.as_ref()};

        Ok(self)
    }

    // Compute SHA256 hash of the input message
    fn hash_message(&mut self, skip_signature: bool, skip_second_signature: bool) -> anyhow::Result<Message> {
        let hash = Sha256::digest(self.to_bytes(skip_signature, skip_second_signature)?); // [u8; 32]
        Ok(Message::from_digest(hash.into()))
    }

    pub(crate) fn sign_schnorr(mut self, passphrase: &str) -> anyhow::Result<Self> {
        self.signature = private_key::sign(&self.hash.hash, passphrase)?;

        Ok(self)
    }

    pub(crate) fn second_sign_schnorr(mut self, passphrase: &str) -> anyhow::Result<Self> {
        let msg = self.hash_message(true, true)?;

        self.second_signature = Some(private_key::sign(msg.as_ref(), passphrase)?);

        Ok(self)
    }

    pub fn to_params(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    fn serialize_multi_payment(&self, buffer: &mut Vec<u8>) -> anyhow::Result<()> {
        if let Asset::MultiPayment { ref payments } = self.asset {
            if payments.len() < 2 {
                anyhow::bail!("Minimum 2 payments required");
            }

            buffer.write_u16::<LittleEndian>(payments.len() as u16)?;

            for payment in payments {
                buffer.write_u64::<LittleEndian>(payment.amount)?;

                let recipient = bs58::decode(&payment.recipient_id)
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .with_check(None)
                    .into_vec()?;

                if recipient.len() != 21 {
                    anyhow::bail!("Invalid recipient length");
                }

                buffer.extend_from_slice(&recipient);
            }
        } else {
            anyhow::bail!("Invalid MultiPayment asset");
        }

        Ok(())
    }
}
