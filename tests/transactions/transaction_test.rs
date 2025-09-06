use arkecosystem_crypto::transactions::deserializer;
use crate::*;

#[test]
fn test_deserialize() {
    let fixture = json_transaction("transfer", "passphrase");
    let serialized = &fixture["serialized"].as_str().unwrap();
    println!("{:?}", serialized);

    let transaction = deserializer::deserialize(serialized);
    println!("{:?}", transaction);
}
