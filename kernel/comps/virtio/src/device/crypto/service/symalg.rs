use bitflags::bitflags;
use ostd::Pod;
use alloc::vec::Vec;
use alloc::vec;
use crate::alloc::string::ToString;
use alloc::string::String;

// Symmetric Algorithms: Cipher
pub const VIRTIO_CRYPTO_NO_CIPHER: u32 = 0;
pub const VIRTIO_CRYPTO_CIPHER_ARC4: u32 = 1;
pub const VIRTIO_CRYPTO_CIPHER_AES_ECB: u32 = 2;
pub const VIRTIO_CRYPTO_CIPHER_AES_CBC: u32 = 3;
pub const VIRTIO_CRYPTO_CIPHER_AES_CTR: u32 = 4;
pub const VIRTIO_CRYPTO_CIPHER_DES_ECB: u32 = 5;
pub const VIRTIO_CRYPTO_CIPHER_DES_CBC: u32 = 6;
pub const VIRTIO_CRYPTO_CIPHER_3DES_ECB: u32 = 7;
pub const VIRTIO_CRYPTO_CIPHER_3DES_CBC: u32 = 8;
pub const VIRTIO_CRYPTO_CIPHER_3DES_CTR: u32 = 9;
pub const VIRTIO_CRYPTO_CIPHER_KASUMI_F8: u32 = 10;
pub const VIRTIO_CRYPTO_CIPHER_SNOW3G_UEA2: u32 = 11;
pub const VIRTIO_CRYPTO_CIPHER_AES_F8: u32 = 12;
pub const VIRTIO_CRYPTO_CIPHER_AES_XTS: u32 = 13;
pub const VIRTIO_CRYPTO_CIPHER_ZUC_EEA3: u32 = 14;

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


pub const VIRTIO_CRYPTO_OP_ENCRYPT: u32 = 1;
pub const VIRTIO_CRYPTO_OP_DECRYPT: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoCipherCreateSessionFlf {
    pub algo: u32,
    pub key_len: u32,
    pub op: u32,
    pub padding: u32,
}

impl Default for VirtioCryptoCipherCreateSessionFlf {
    fn default() -> Self {
        Self {
            algo: VIRTIO_CRYPTO_CIPHER_AES_CBC,
            key_len: 16,
            op: VIRTIO_CRYPTO_OP_ENCRYPT,
            padding: 0,
        }
    }
}

impl VirtioCryptoCipherCreateSessionFlf {
    pub fn new(algo: u32, op: u32) -> Self {
        let key_len = match algo {
            VIRTIO_CRYPTO_CIPHER_ARC4 => 16,
            VIRTIO_CRYPTO_CIPHER_AES_ECB => 16,
            VIRTIO_CRYPTO_CIPHER_AES_CBC => 16,
            VIRTIO_CRYPTO_CIPHER_AES_CTR => 16,
            VIRTIO_CRYPTO_CIPHER_DES_ECB => 8,
            VIRTIO_CRYPTO_CIPHER_DES_CBC => 8,
            VIRTIO_CRYPTO_CIPHER_3DES_ECB => 24,
            VIRTIO_CRYPTO_CIPHER_3DES_CBC => 24,
            VIRTIO_CRYPTO_CIPHER_3DES_CTR => 24,
            VIRTIO_CRYPTO_CIPHER_KASUMI_F8 => 16,
            VIRTIO_CRYPTO_CIPHER_SNOW3G_UEA2 => 16,
            VIRTIO_CRYPTO_CIPHER_AES_F8 => 16,
            VIRTIO_CRYPTO_CIPHER_AES_XTS => 32,
            VIRTIO_CRYPTO_CIPHER_ZUC_EEA3 => 16,
            _ => 0,
        };
        Self {
            algo,
            key_len,
            op,
            padding: 0,
        }
    }
}


// Symmetric Algorithms: The Chain algorithm
pub const VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER: u32 = 1;
pub const VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH: u32 = 2;
pub const VIRTIO_CRYPTO_SYM_HASH_MODE_PLAIN: u32 = 1;
pub const VIRTIO_CRYPTO_SYM_HASH_MODE_AUTH: u32 = 2;
pub const VIRTIO_CRYPTO_SYM_HASH_MODE_NESTED: u32 = 3;
pub const VIRTIO_CRYPTO_ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE: u32 = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoChainAlgSessionFlf {
    pub alg_chain_order: u32,
    pub hash_mode: u32,
    pub cipher_hdr: VirtioCryptoCipherCreateSessionFlf,
    pub algo_flf: [u8; VIRTIO_CRYPTO_ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE as usize],
    pub aad_len: u32,
    pub padding: u32,
}

impl VirtioCryptoChainAlgSessionFlf {
    pub fn new(alg_chain_order: u32, hash_mode: u32, cipher_hdr: VirtioCryptoCipherCreateSessionFlf, algo_flf: [u8; VIRTIO_CRYPTO_ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE as usize], aad_len: u32) -> Self {
        Self {
            alg_chain_order,
            hash_mode,
            cipher_hdr,
            algo_flf,
            aad_len,
            padding: 0,
        }
    }
}

// Symmetric Algorithms
pub const VIRTIO_CRYPTO_SYM_OP_NONE: u32 = 0;
pub const VIRTIO_CRYPTO_SYM_OP_CIPHER: u32 = 1;
pub const VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING: u32 = 2;
pub const VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE: u32 = 48;

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoSymCreateSessionFlf {
    pub op_flf: [u8; VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE as usize], 
    // Should be VirtioCryptoCipherSessionFlf or VirtioCryptoAlgChainSessionFlf
    pub op_type: u32,
    pub padding: u32,
}

impl VirtioCryptoSymCreateSessionFlf {
    pub fn new(op_flf: &[u8], op_type: u32) -> Self {
        let mut flf = [0; VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE as usize];
        let len = op_flf.len().min(VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE as usize);
        flf[..len].copy_from_slice(&op_flf[..len]);
        Self {
            op_flf: flf,
            op_type,
            padding: 0,
        }
    }
}