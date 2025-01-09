use bitflags::bitflags;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;
use crate::device::crypto::config::VirtioCryptoConfig;
use crate::device::crypto::service::{
    cipher::SupportedCiphers,
    hash::SupportedHashes,
    mac::SupportedMacs,
    aead::SupportedAeads,
    akcipher::SupportedAkCiphers,
};

pub const VIRTIO_CRYPTO_SERVICE_CIPHER:u32 = 0;
pub const VIRTIO_CRYPTO_SERVICE_HASH:u32 = 1;
pub const VIRTIO_CRYPTO_SERVICE_MAC:u32 = 2;
pub const VIRTIO_CRYPTO_SERVICE_AEAD:u32 = 3;
pub const VIRTIO_CRYPTO_SERVICE_AKCIPHER:u32 = 4;

pub struct CryptoServiceMap {
    pub supported_ciphers: SupportedCiphers,
    pub supported_hashes: SupportedHashes,
    pub supported_macs: SupportedMacs,
    pub supported_aeads: SupportedAeads,
    pub supported_akciphers: SupportedAkCiphers,
}

impl CryptoServiceMap {
    pub fn new(config: VirtioCryptoConfig) -> CryptoServiceMap {
        Self::load_crypto_algorithms(config)
    }

    pub fn load_crypto_algorithms(config: VirtioCryptoConfig) -> Self {
        // Crypto Services
        let supported_crypto_services = SupportedCryptoServices::from_u32(config.crypto_services);
        // CIPHER
        let cipher_config = if supported_crypto_services.contains(SupportedCryptoServices::CIPHER) {
            ((config.cipher_algo_h as u64) << 32) | config.cipher_algo_l as u64
        } else {0};
        let supported_ciphers = SupportedCiphers::from_u64(cipher_config);

        // HASH
        let hash_config = if supported_crypto_services.contains(SupportedCryptoServices::HASH) {
            config.hash_algo
        } else {0};
        let supported_hashes = SupportedHashes::from_u32(hash_config);

        // MAC
        let mac_config = if supported_crypto_services.contains(SupportedCryptoServices::MAC) {
            ((config.mac_algo_h as u64) << 32) | config.mac_algo_l as u64
        } else {0};
        let supported_macs = SupportedMacs::from_u64(mac_config);

        // AEAD
        let aead_config = if supported_crypto_services.contains(SupportedCryptoServices::AEAD) {
            config.aead_algo
        } else {0};
        let supported_aeads = SupportedAeads::from_u32(aead_config);

        // AKCIPHER
        let akcipher_config = if supported_crypto_services.contains(SupportedCryptoServices::AKCIPHER) {
            config.akcipher_algo
        } else {0};
        let supported_akciphers = SupportedAkCiphers::from_u32(akcipher_config);

        Self {
            supported_ciphers,
            supported_hashes,
            supported_macs,
            supported_aeads,
            supported_akciphers,
        }
    }
}



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
