use bitflags::bitflags;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;

bitflags! {
    pub struct SupportedCryptoServices: u32 {
        const CIPHER                    = 1 << 0;  // 0x0001
        const HASH                      = 1 << 1;  // 0x0002
        const MAC                       = 1 << 2;  // 0x0004
        const AEAD                      = 1 << 3;  // 0x0008
        const AKCIPHER                  = 1 << 4;  // 0x0010
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
