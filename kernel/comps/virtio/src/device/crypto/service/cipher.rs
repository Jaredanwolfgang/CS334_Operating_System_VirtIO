use bitflags::bitflags;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;

const VIRTIO_CRYPTO_NO_CIPHER: u32 = 0;
const VIRTIO_CRYPTO_CIPHER_ARC4: u32 = 1;
const VIRTIO_CRYPTO_CIPHER_AES_ECB: u32 = 2;
const VIRTIO_CRYPTO_CIPHER_AES_CBC: u32 = 3;
const VIRTIO_CRYPTO_CIPHER_AES_CTR: u32 = 4;
const VIRTIO_CRYPTO_CIPHER_DES_ECB: u32 = 5;
const VIRTIO_CRYPTO_CIPHER_DES_CBC: u32 = 6;
const VIRTIO_CRYPTO_CIPHER_3DES_ECB: u32 = 7;
const VIRTIO_CRYPTO_CIPHER_3DES_CBC: u32 = 8;
const VIRTIO_CRYPTO_CIPHER_3DES_CTR: u32 = 9;
const VIRTIO_CRYPTO_CIPHER_KASUMI_F8: u32 = 10;
const VIRTIO_CRYPTO_CIPHER_SNOW3G_UEA2: u32 = 11;
const VIRTIO_CRYPTO_CIPHER_AES_F8: u32 = 12;
const VIRTIO_CRYPTO_CIPHER_AES_XTS: u32 = 13;
const VIRTIO_CRYPTO_CIPHER_ZUC_EEA3: u32 = 14;

bitflags! {
    pub struct SupportedCiphers: u64 {
        const NO_CIPHER                 = 1 << VIRTIO_CRYPTO_NO_CIPHER;
        const ARC4                      = 1 << VIRTIO_CRYPTO_CIPHER_ARC4;
        const AES_ECB                   = 1 << VIRTIO_CRYPTO_CIPHER_AES_ECB;
        const AES_CBC                   = 1 << VIRTIO_CRYPTO_CIPHER_AES_CBC;
        const AES_CTR                   = 1 << VIRTIO_CRYPTO_CIPHER_AES_CTR;
        const DES_ECB                   = 1 << VIRTIO_CRYPTO_CIPHER_DES_ECB;
        const DES_CBC                   = 1 << VIRTIO_CRYPTO_CIPHER_DES_CBC;
        const THREE_DES_ECB             = 1 << VIRTIO_CRYPTO_CIPHER_3DES_ECB;
        const THREE_DES_CBC             = 1 << VIRTIO_CRYPTO_CIPHER_3DES_CBC;
        const THREE_DES_CTR             = 1 << VIRTIO_CRYPTO_CIPHER_3DES_CTR;
        const KASUMI_F8                 = 1 << VIRTIO_CRYPTO_CIPHER_KASUMI_F8;
        const SNOW3G_UEA2               = 1 << VIRTIO_CRYPTO_CIPHER_SNOW3G_UEA2;
        const AES_F8                    = 1 << VIRTIO_CRYPTO_CIPHER_AES_F8;
        const AES_XTS                   = 1 << VIRTIO_CRYPTO_CIPHER_AES_XTS;
        const ZUC_EEA3                  = 1 << VIRTIO_CRYPTO_CIPHER_ZUC_EEA3;
    }
}

impl SupportedCiphers {
    pub fn from_u64(value: u64) -> Self {
        SupportedCiphers::from_bits_truncate(value)
    }

    pub fn get_supported_ciphers_name(&self) -> Vec<String> {
        let mut supported_ciphers_name = Vec::new();
        if self.contains(SupportedCiphers::NO_CIPHER) {
            supported_ciphers_name.push("No Cipher".to_string());
        }
        if self.contains(SupportedCiphers::ARC4) {
            supported_ciphers_name.push("ARC4".to_string());
        }
        if self.contains(SupportedCiphers::AES_ECB) {
            supported_ciphers_name.push("AES ECB".to_string());
        }
        if self.contains(SupportedCiphers::AES_CBC) {
            supported_ciphers_name.push("AES CBC".to_string());
        }
        if self.contains(SupportedCiphers::AES_CTR) {
            supported_ciphers_name.push("AES CTR".to_string());
        }
        if self.contains(SupportedCiphers::DES_ECB) {
            supported_ciphers_name.push("DES ECB".to_string());
        }
        if self.contains(SupportedCiphers::DES_CBC) {
            supported_ciphers_name.push("DES CBC".to_string());
        }
        if self.contains(SupportedCiphers::THREE_DES_ECB) {
            supported_ciphers_name.push("3DES ECB".to_string());
        }
        if self.contains(SupportedCiphers::THREE_DES_CBC) {
            supported_ciphers_name.push("3DES CBC".to_string());
        }
        if self.contains(SupportedCiphers::THREE_DES_CTR) {
            supported_ciphers_name.push("3DES CTR".to_string());
        }
        if self.contains(SupportedCiphers::KASUMI_F8) {
            supported_ciphers_name.push("Kasumi F8".to_string());
        }
        if self.contains(SupportedCiphers::SNOW3G_UEA2) {
            supported_ciphers_name.push("SNOW3G UEA2".to_string());
        }
        if self.contains(SupportedCiphers::AES_F8) {
            supported_ciphers_name.push("AES F8".to_string());
        }
        if self.contains(SupportedCiphers::AES_XTS) {
            supported_ciphers_name.push("AES XTS".to_string());
        }
        if self.contains(SupportedCiphers::ZUC_EEA3) {
            supported_ciphers_name.push("ZUC EEA3".to_string());
        }
        supported_ciphers_name
    }
}
