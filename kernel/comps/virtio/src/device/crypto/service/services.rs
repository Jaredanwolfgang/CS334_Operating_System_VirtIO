use bitflags::bitflags;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;

pub const VIRTIO_CRYPTO_SERVICE_CIPHER:u32 = 0;
pub const VIRTIO_CRYPTO_SERVICE_HASH:u32 = 1;
pub const VIRTIO_CRYPTO_SERVICE_MAC:u32 = 2;
pub const VIRTIO_CRYPTO_SERVICE_AEAD:u32 = 3;
pub const VIRTIO_CRYPTO_SERVICE_AKCIPHER:u32 = 4; 

bitflags! {
    pub struct SupportedCryptoServices: u32 {
        const CIPHER                    = 1 << VIRTIO_CRYPTO_SERVICE_CIPHER;
        const HASH                      = 1 << VIRTIO_CRYPTO_SERVICE_HASH;
        const MAC                       = 1 << VIRTIO_CRYPTO_SERVICE_MAC;
        const AEAD                      = 1 << VIRTIO_CRYPTO_SERVICE_AEAD;
        const AKCIPHER                  = 1 << VIRTIO_CRYPTO_SERVICE_AKCIPHER;
    }
}

impl SupportedCryptoServices {
    pub fn from_u32(value: u32) -> Self {
        SupportedCryptoServices::from_bits_truncate(value)
    }

    pub fn get_supported_crypto_services_name(&self) -> Vec<String> {
        let mut supported_crypto_services_name = Vec::new();
        if self.contains(SupportedCryptoServices::CIPHER) {
            supported_crypto_services_name.push("CIPHER".to_string());
        }
        if self.contains(SupportedCryptoServices::HASH) {
            supported_crypto_services_name.push("HASH".to_string());
        }
        if self.contains(SupportedCryptoServices::MAC) {
            supported_crypto_services_name.push("MAC".to_string());
        }
        if self.contains(SupportedCryptoServices::AEAD) {
            supported_crypto_services_name.push("AEAD".to_string());
        }
        if self.contains(SupportedCryptoServices::AKCIPHER) {
            supported_crypto_services_name.push("AKCIPHER".to_string());
        }
        supported_crypto_services_name
    }
}
