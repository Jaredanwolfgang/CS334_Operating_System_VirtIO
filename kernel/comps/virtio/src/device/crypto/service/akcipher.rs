use bitflags::bitflags;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;

const VIRTIO_CRYPTO_NO_AKCIPHER: u32 = 0;
const VIRTIO_CRYPTO_AKCIPHER_RSA: u32 = 1;
const VIRTIO_CRYPTO_AKCIPHER_ECDSA: u32 = 2;

bitflags! {
    pub struct SupportedAkCiphers: u32 {
        const NO_AKCIPHER                  = 1 << VIRTIO_CRYPTO_NO_AKCIPHER;                   // 0x0001
        const RSA                          = 1 << VIRTIO_CRYPTO_AKCIPHER_RSA;                   // 0x0002
        const ECDSA                        = 1 << VIRTIO_CRYPTO_AKCIPHER_ECDSA;                 // 0x0004
    }
}

impl SupportedAkCiphers {
    pub fn from_u32(value: u32) -> Self {
        SupportedAkCiphers::from_bits_truncate(value)
    }

    pub fn get_supported_akciphers_name(&self) -> Vec<String> {
        let mut supported_akciphers_name = Vec::new();
        if self.contains(SupportedAkCiphers::NO_AKCIPHER) {
            supported_akciphers_name.push("No AKCipher".to_string());
        }
        if self.contains(SupportedAkCiphers::RSA) {
            supported_akciphers_name.push("RSA".to_string());
        }
        if self.contains(SupportedAkCiphers::ECDSA) {
            supported_akciphers_name.push("ECDSA".to_string());
        }
        supported_akciphers_name
    }
}