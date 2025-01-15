use aster_crypto::get_device;
use ostd::early_println;
use spin::Once;
use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;

static ENCRYPTED_DATA: Once<Vec<u8>> = Once::new();
static PADDING: Once<usize> = Once::new();


pub fn encrypt(input: &[u8]) {
    let device = get_device("virtio-crypto").unwrap();
    let mut padded_data = input.to_vec();
    let padding = 16 - (padded_data.len() % 16);
    padded_data.extend(vec![0_u8; padding]);
    let cipher_key = [0_u8; 16];
    let encrypted_data = device.cipher_encrypt(&padded_data, &cipher_key);
    ENCRYPTED_DATA.call_once(|| encrypted_data);
    PADDING.call_once(|| padding);
}

pub fn decrypt() {
    let device = get_device("virtio-crypto").unwrap();
    let encrypted_data = ENCRYPTED_DATA.get().unwrap();
    let cipher_key = [0_u8; 16];
    let decrypted_data = device.cipher_decrypt(encrypted_data, &cipher_key);
    // Remove padding and print decrypted data as string
    let padding = PADDING.get().unwrap();
    let decrypted_data = decrypted_data[..decrypted_data.len() - padding].to_vec();
    match String::from_utf8(decrypted_data) {
        Ok(string) => {
            early_println!("Decrypted string: {}", string);
        },
        Err(e) => {
            early_println!("Failed to decode bytes: {}", e);
        }
    }
}