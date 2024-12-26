use bitflags::bitflags;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;

bitflags! {
    pub struct SupportedMacs: u64 {
        const NO_MAC                           = 1 << 0;   // 0x0001
        const HMAC_MD5                         = 1 << 1;   // 0x0002
        const HMAC_SHA1                        = 1 << 2;   // 0x0004
        const HMAC_SHA_224                     = 1 << 3;   // 0x0008
        const HMAC_SHA_256                     = 1 << 4;   // 0x0010
        const HMAC_SHA_384                     = 1 << 5;   // 0x0020
        const HMAC_SHA_512                     = 1 << 6;   // 0x0040
        const CMAC_3DES                        = 1 << 25;  // 0x02000000
        const CMAC_AES                         = 1 << 26;  // 0x04000000
        const KASUMI_F9                        = 1 << 27;  // 0x08000000
        const SNOW3G_UIA2                      = 1 << 28;  // 0x10000000
        const GMAC_AES                         = 1 << 41;  // 0x200000000000
        const GMAC_TWOFISH                     = 1 << 42;  // 0x400000000000
        const CBCMAC_AES                       = 1 << 49;  // 0x800000000000000
        const CBCMAC_KASUMI_F9                 = 1 << 50;  // 0x1000000000000000
        const XCBC_AES                         = 1 << 53;  // 0x4000000000000000
        const ZUC_EIA3                         = 1 << 54;  // 0x8000000000000000
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
