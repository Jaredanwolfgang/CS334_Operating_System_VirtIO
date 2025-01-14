use alloc::{string::String, vec::Vec};

use bitflags::bitflags;

use crate::alloc::string::ToString;

const VIRTIO_CRYPTO_NO_AEAD: u32 = 0;
const VIRTIO_CRYPTO_AEAD_GCM: u32 = 1;
const VIRTIO_CRYPTO_AEAD_CCM: u32 = 2;
const VIRTIO_CRYPTO_AEAD_CHACHA20_POLY1305: u32 = 3;

bitflags! {
    pub struct SupportedAeads: u32 {
        const NO_AEAD                      = 1 << VIRTIO_CRYPTO_NO_AEAD;                      // 0x0001
        const GCM                          = 1 << VIRTIO_CRYPTO_AEAD_GCM;                      // 0x0002
        const CCM                          = 1 << VIRTIO_CRYPTO_AEAD_CCM;                      // 0x0004
        const CHACHA20_POLY1305            = 1 << VIRTIO_CRYPTO_AEAD_CHACHA20_POLY1305;        // 0x0008
    }
}

impl SupportedAeads {
    pub fn from_u32(value: u32) -> Self {
        SupportedAeads::from_bits_truncate(value)
    }

    pub fn get_supported_aeads_name(&self) -> Vec<String> {
        let mut supported_aeads_name = Vec::new();
        if self.contains(SupportedAeads::NO_AEAD) {
            supported_aeads_name.push("No AEAD".to_string());
        }
        if self.contains(SupportedAeads::GCM) {
            supported_aeads_name.push("GCM".to_string());
        }
        if self.contains(SupportedAeads::CCM) {
            supported_aeads_name.push("CCM".to_string());
        }
        if self.contains(SupportedAeads::CHACHA20_POLY1305) {
            supported_aeads_name.push("ChaCha20-Poly1305".to_string());
        }
        supported_aeads_name
    }
}
