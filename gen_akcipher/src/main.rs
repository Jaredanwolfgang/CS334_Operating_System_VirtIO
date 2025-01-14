use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, pkcs1::EncodeRsaPublicKey};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate private key
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;

    // Convert private key to Vec<u8> (PKCS#1 format)
    let private_key_bytes = private_key.to_pkcs1_der()?.as_bytes().to_vec();
    println!("Private Key length {:?}", private_key_bytes.len());
    println!("Private Key (PKCS#1) as Vec<u8>: vec!{:?}", private_key_bytes);

    // Get public key from private key
    let public_key = RsaPublicKey::from(&private_key);

    // Convert public key to Vec<u8> (PKCS#1 format)
    let public_key_bytes = public_key.to_pkcs1_der()?.as_bytes().to_vec();
    println!("Public Key length {:?}", public_key_bytes.len());
    println!("Public Key (PKCS#1) as Vec<u8>: vec!{:?}", public_key_bytes);

    Ok(())
}

