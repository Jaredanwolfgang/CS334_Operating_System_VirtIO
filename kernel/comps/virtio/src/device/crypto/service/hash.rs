use bitflags::bitflags;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;

pub const VIRTIO_CRYPTO_NO_HASH: u32 = 0;
pub const VIRTIO_CRYPTO_HASH_MD5: u32 = 1;
pub const VIRTIO_CRYPTO_HASH_SHA1: u32 = 2;
pub const VIRTIO_CRYPTO_HASH_SHA_224: u32 = 3;
pub const VIRTIO_CRYPTO_HASH_SHA_256: u32 = 4;
pub const VIRTIO_CRYPTO_HASH_SHA_384: u32 = 5;
pub const VIRTIO_CRYPTO_HASH_SHA_512: u32 = 6;
pub const VIRTIO_CRYPTO_HASH_SHA3_224: u32 = 7;
pub const VIRTIO_CRYPTO_HASH_SHA3_256: u32 = 8;
pub const VIRTIO_CRYPTO_HASH_SHA3_384: u32 = 9;
pub const VIRTIO_CRYPTO_HASH_SHA3_512: u32 = 10;
pub const VIRTIO_CRYPTO_HASH_SHA3_SHAKE128: u32 = 11;
pub const VIRTIO_CRYPTO_HASH_SHA3_SHAKE256: u32 = 12;

bitflags! {
    pub struct SupportedHashes: u32 {
        const NO_HASH                       = 1 << VIRTIO_CRYPTO_NO_HASH;                       // 0x0001
        const MD5                           = 1 << VIRTIO_CRYPTO_HASH_MD5;                       // 0x0002
        const SHA1                          = 1 << VIRTIO_CRYPTO_HASH_SHA1;                      // 0x0004
        const SHA_224                       = 1 << VIRTIO_CRYPTO_HASH_SHA_224;                   // 0x0008
        const SHA_256                       = 1 << VIRTIO_CRYPTO_HASH_SHA_256;                   // 0x0010
        const SHA_384                       = 1 << VIRTIO_CRYPTO_HASH_SHA_384;                   // 0x0020
        const SHA_512                       = 1 << VIRTIO_CRYPTO_HASH_SHA_512;                   // 0x0040
        const SHA3_224                      = 1 << VIRTIO_CRYPTO_HASH_SHA3_224;                  // 0x0080
        const SHA3_256                      = 1 << VIRTIO_CRYPTO_HASH_SHA3_256;                  // 0x0100
        const SHA3_384                      = 1 << VIRTIO_CRYPTO_HASH_SHA3_384;                  // 0x0200
        const SHA3_512                      = 1 << VIRTIO_CRYPTO_HASH_SHA3_512;                  // 0x0400
        const SHA3_SHAKE128                 = 1 << VIRTIO_CRYPTO_HASH_SHA3_SHAKE128;             // 0x0800
        const SHA3_SHAKE256                 = 1 << VIRTIO_CRYPTO_HASH_SHA3_SHAKE256;             // 0x1000
    }
}

impl SupportedHashes {
    pub fn from_u32(value: u32) -> Self {
        SupportedHashes::from_bits_truncate(value)
    }

    pub fn get_supported_hashes_name(&self) -> Vec<String> {
        let mut supported_hashes_name = Vec::new();
        if self.contains(SupportedHashes::NO_HASH) {
            supported_hashes_name.push("No Hash".to_string());
        }
        if self.contains(SupportedHashes::MD5) {
            supported_hashes_name.push("MD5".to_string());
        }
        if self.contains(SupportedHashes::SHA1) {
            supported_hashes_name.push("SHA1".to_string());
        }
        if self.contains(SupportedHashes::SHA_224) {
            supported_hashes_name.push("SHA-224".to_string());
        }
        if self.contains(SupportedHashes::SHA_256) {
            supported_hashes_name.push("SHA-256".to_string());
        }
        if self.contains(SupportedHashes::SHA_384) {
            supported_hashes_name.push("SHA-384".to_string());
        }
        if self.contains(SupportedHashes::SHA_512) {
            supported_hashes_name.push("SHA-512".to_string());
        }
        if self.contains(SupportedHashes::SHA3_224) {
            supported_hashes_name.push("SHA3-224".to_string());
        }
        if self.contains(SupportedHashes::SHA3_256) {
            supported_hashes_name.push("SHA3-256".to_string());
        }
        if self.contains(SupportedHashes::SHA3_384) {
            supported_hashes_name.push("SHA3-384".to_string());
        }
        if self.contains(SupportedHashes::SHA3_512) {
            supported_hashes_name.push("SHA3-512".to_string());
        }
        if self.contains(SupportedHashes::SHA3_SHAKE128) {
            supported_hashes_name.push("SHA3-SHAKE128".to_string());
        }
        if self.contains(SupportedHashes::SHA3_SHAKE256) {
            supported_hashes_name.push("SHA3-SHAKE256".to_string());
        }
        supported_hashes_name
    }
}


pub struct VirtioCryptoHashCreateSessionFlf {
    pub algo: u32,
    pub hash_result_len: u32,
}

