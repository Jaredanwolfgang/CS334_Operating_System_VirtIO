use alloc::{string::String, vec::Vec};

use bitflags::bitflags;
use ostd::Pod;

use crate::alloc::string::ToString;

const VIRTIO_CRYPTO_NO_MAC: u32 = 0;
const VIRTIO_CRYPTO_MAC_HMAC_MD5: u32 = 1;
const VIRTIO_CRYPTO_MAC_HMAC_SHA1: u32 = 2;
const VIRTIO_CRYPTO_MAC_HMAC_SHA_224: u32 = 3;
const VIRTIO_CRYPTO_MAC_HMAC_SHA_256: u32 = 4;
const VIRTIO_CRYPTO_MAC_HMAC_SHA_384: u32 = 5;
const VIRTIO_CRYPTO_MAC_HMAC_SHA_512: u32 = 6;
const VIRTIO_CRYPTO_MAC_CMAC_3DES: u32 = 25;
const VIRTIO_CRYPTO_MAC_CMAC_AES: u32 = 26;
const VIRTIO_CRYPTO_MAC_KASUMI_F9: u32 = 27;
const VIRTIO_CRYPTO_MAC_SNOW3G_UIA2: u32 = 28;
const VIRTIO_CRYPTO_MAC_GMAC_AES: u32 = 41;
const VIRTIO_CRYPTO_MAC_GMAC_TWOFISH: u32 = 42;
const VIRTIO_CRYPTO_MAC_CBCMAC_AES: u32 = 49;
const VIRTIO_CRYPTO_MAC_CBCMAC_KASUMI_F9: u32 = 50;
const VIRTIO_CRYPTO_MAC_XCBC_AES: u32 = 53;
const VIRTIO_CRYPTO_MAC_ZUC_EIA3: u32 = 54;

bitflags! {
    pub struct SupportedMacs: u64 {
        const NO_MAC                           = 1 << VIRTIO_CRYPTO_NO_MAC;                        // 0x0001
        const HMAC_MD5                         = 1 << VIRTIO_CRYPTO_MAC_HMAC_MD5;                  // 0x0002
        const HMAC_SHA1                        = 1 << VIRTIO_CRYPTO_MAC_HMAC_SHA1;                 // 0x0004
        const HMAC_SHA_224                     = 1 << VIRTIO_CRYPTO_MAC_HMAC_SHA_224;              // 0x0008
        const HMAC_SHA_256                     = 1 << VIRTIO_CRYPTO_MAC_HMAC_SHA_256;              // 0x0010
        const HMAC_SHA_384                     = 1 << VIRTIO_CRYPTO_MAC_HMAC_SHA_384;              // 0x0020
        const HMAC_SHA_512                     = 1 << VIRTIO_CRYPTO_MAC_HMAC_SHA_512;              // 0x0040
        const CMAC_3DES                        = 1 << VIRTIO_CRYPTO_MAC_CMAC_3DES;                 // 0x02000000
        const CMAC_AES                         = 1 << VIRTIO_CRYPTO_MAC_CMAC_AES;                  // 0x04000000
        const KASUMI_F9                        = 1 << VIRTIO_CRYPTO_MAC_KASUMI_F9;                 // 0x08000000
        const SNOW3G_UIA2                      = 1 << VIRTIO_CRYPTO_MAC_SNOW3G_UIA2;               // 0x10000000
        const GMAC_AES                         = 1 << VIRTIO_CRYPTO_MAC_GMAC_AES;                  // 0x200000000000
        const GMAC_TWOFISH                     = 1 << VIRTIO_CRYPTO_MAC_GMAC_TWOFISH;              // 0x400000000000
        const CBCMAC_AES                       = 1 << VIRTIO_CRYPTO_MAC_CBCMAC_AES;                // 0x800000000000000
        const CBCMAC_KASUMI_F9                 = 1 << VIRTIO_CRYPTO_MAC_CBCMAC_KASUMI_F9;          // 0x1000000000000000
        const XCBC_AES                         = 1 << VIRTIO_CRYPTO_MAC_XCBC_AES;                  // 0x4000000000000000
        const ZUC_EIA3                         = 1 << VIRTIO_CRYPTO_MAC_ZUC_EIA3;                  // 0x8000000000000000
    }
}

impl SupportedMacs {
    pub fn from_u64(value: u64) -> Self {
        SupportedMacs::from_bits_truncate(value)
    }

    pub fn get_supported_macs_name(&self) -> Vec<String> {
        let mut supported_macs_name = Vec::new();
        if self.contains(SupportedMacs::NO_MAC) {
            supported_macs_name.push("No MAC".to_string());
        }
        if self.contains(SupportedMacs::HMAC_MD5) {
            supported_macs_name.push("HMAC MD5".to_string());
        }
        if self.contains(SupportedMacs::HMAC_SHA1) {
            supported_macs_name.push("HMAC SHA1".to_string());
        }
        if self.contains(SupportedMacs::HMAC_SHA_224) {
            supported_macs_name.push("HMAC SHA-224".to_string());
        }
        if self.contains(SupportedMacs::HMAC_SHA_256) {
            supported_macs_name.push("HMAC SHA-256".to_string());
        }
        if self.contains(SupportedMacs::HMAC_SHA_384) {
            supported_macs_name.push("HMAC SHA-384".to_string());
        }
        if self.contains(SupportedMacs::HMAC_SHA_512) {
            supported_macs_name.push("HMAC SHA-512".to_string());
        }
        if self.contains(SupportedMacs::CMAC_3DES) {
            supported_macs_name.push("CMAC 3DES".to_string());
        }
        if self.contains(SupportedMacs::CMAC_AES) {
            supported_macs_name.push("CMAC AES".to_string());
        }
        if self.contains(SupportedMacs::KASUMI_F9) {
            supported_macs_name.push("KASUMI F9".to_string());
        }
        if self.contains(SupportedMacs::SNOW3G_UIA2) {
            supported_macs_name.push("SNOW3G UIA2".to_string());
        }
        if self.contains(SupportedMacs::GMAC_AES) {
            supported_macs_name.push("GMAC AES".to_string());
        }
        if self.contains(SupportedMacs::GMAC_TWOFISH) {
            supported_macs_name.push("GMAC Twofish".to_string());
        }
        if self.contains(SupportedMacs::CBCMAC_AES) {
            supported_macs_name.push("CBCMAC AES".to_string());
        }
        if self.contains(SupportedMacs::CBCMAC_KASUMI_F9) {
            supported_macs_name.push("CBCMAC KASUMI F9".to_string());
        }
        if self.contains(SupportedMacs::XCBC_AES) {
            supported_macs_name.push("XCBC AES".to_string());
        }
        if self.contains(SupportedMacs::ZUC_EIA3) {
            supported_macs_name.push("ZUC EIA3".to_string());
        }
        supported_macs_name
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoMacCreateSessionFlf {
    pub algo: u32,
    pub hash_result_len: u32,
    pub auth_key_len: u32,
    pub padding: u32,
}

impl VirtioCryptoMacCreateSessionFlf {
    pub fn new(algo: u32) -> Self {
        let (hash_result_len, auth_key_len) = match algo {
            VIRTIO_CRYPTO_MAC_HMAC_MD5 => (16, 16),
            VIRTIO_CRYPTO_MAC_HMAC_SHA1 => (20, 20),
            VIRTIO_CRYPTO_MAC_HMAC_SHA_224 => (28, 28),
            VIRTIO_CRYPTO_MAC_HMAC_SHA_256 => (32, 32),
            VIRTIO_CRYPTO_MAC_HMAC_SHA_384 => (48, 48),
            VIRTIO_CRYPTO_MAC_HMAC_SHA_512 => (64, 64),
            VIRTIO_CRYPTO_MAC_CMAC_3DES => (16, 16),
            VIRTIO_CRYPTO_MAC_CMAC_AES => (16, 16),
            VIRTIO_CRYPTO_MAC_KASUMI_F9 => (4, 16),
            VIRTIO_CRYPTO_MAC_SNOW3G_UIA2 => (4, 16),
            VIRTIO_CRYPTO_MAC_GMAC_AES => (16, 16),
            VIRTIO_CRYPTO_MAC_GMAC_TWOFISH => (16, 16),
            VIRTIO_CRYPTO_MAC_CBCMAC_AES => (16, 16),
            VIRTIO_CRYPTO_MAC_CBCMAC_KASUMI_F9 => (4, 16),
            VIRTIO_CRYPTO_MAC_XCBC_AES => (16, 16),
            VIRTIO_CRYPTO_MAC_ZUC_EIA3 => (4, 16),
            _ => (0, 0),
        };
        Self {
            algo,
            hash_result_len,
            auth_key_len,
            padding: 0,
        }
    }
}
