use bitflags::bitflags;
use ostd::Pod;
use alloc::vec::Vec;
use crate::alloc::string::ToString;
use alloc::string::String;

use super::hash::*;
use super::mac::*;

// ControlQ
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
    // Should be VirtioCryptoHashCreateSessionFlf or VirtioCryptoMacCreateSessionFlf
    pub aad_len: u32,
    pub padding: u32,
}

impl VirtioCryptoChainAlgSessionFlf {
    pub fn new(alg_chain_order: u32, hash_mode: u32, hash_algo: u32, cipher_hdr: VirtioCryptoCipherCreateSessionFlf, aad_len: u32) -> Self {
        let algo_flf = match hash_mode {
            VIRTIO_CRYPTO_SYM_HASH_MODE_PLAIN => {
                let hash_session = VirtioCryptoHashCreateSessionFlf::new(hash_algo);
                let hash_flf = hash_session.as_bytes();
                let mut flf = [0; VIRTIO_CRYPTO_ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE as usize];
                flf[..hash_flf.len()].copy_from_slice(&hash_flf);
                flf
            },
            VIRTIO_CRYPTO_SYM_HASH_MODE_AUTH => {
                let mac_session = VirtioCryptoMacCreateSessionFlf::new(hash_algo);
                let mac_flf = mac_session.as_bytes();
                let mut flf = [0; VIRTIO_CRYPTO_ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE as usize];
                flf[..mac_flf.len()].copy_from_slice(&mac_flf);
                flf
            },
            VIRTIO_CRYPTO_SYM_HASH_MODE_NESTED => {
                let hash_session = VirtioCryptoHashCreateSessionFlf::new(hash_algo);
                let hash_flf = hash_session.as_bytes();
                let mut flf = [0; VIRTIO_CRYPTO_ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE as usize];
                flf[..hash_flf.len()].copy_from_slice(&hash_flf);
                flf
            },
            _ => unimplemented!("Unsupported hash mode"),
        };
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

// DataQ
// Symmetric Algorithms: Cipher
/*
struct virtio_crypto_cipher_data_flf { 
    /* 
     * Byte Length of valid IV/Counter data pointed to by the below iv data. 
     * 
     * For block ciphers in CBC or F8 mode, or for Kasumi in F8 mode, or for 
     *   SNOW3G in UEA2 mode, this is the length of the IV (which 
     *   must be the same as the block length of the cipher). 
     * For block ciphers in CTR mode, this is the length of the counter 
     *   (which must be the same as the block length of the cipher). 
     */ 
    le32 iv_len; 
    /* length of source data */ 
    le32 src_data_len; 
    /* length of destination data */ 
    le32 dst_data_len; 
    le32 padding; 
}; 

struct virtio_crypto_cipher_data_vlf { 
    /* Device read only portion */ 
 
    /* 
     * Initialization Vector or Counter data. 
     * 
     * For block ciphers in CBC or F8 mode, or for Kasumi in F8 mode, or for 
     *   SNOW3G in UEA2 mode, this is the Initialization Vector (IV) 
     *   value. 
     * For block ciphers in CTR mode, this is the counter. 
     * For AES-XTS, this is the 128bit tweak, i, from IEEE Std 1619-2007. 
     * 
     * The IV/Counter will be updated after every partial cryptographic 
     * operation. 
     */ 
    u8 iv[iv_len]; 
    /* Source data */ 
    u8 src_data[src_data_len]; 
 
    /* Device write only portion */ 
    /* Destination data */ 
    u8 dst_data[dst_data_len]; 
};
*/
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoCipherDataFlf {
    pub iv_len: u32,
    pub src_data_len: u32,
    pub dst_data_len: u32,
    pub padding: u32,
}

// Symmetric Algorithms: The Chain algorithm
/*
struct virtio_crypto_alg_chain_data_flf { 
    le32 iv_len; 
    /* Length of source data */ 
    le32 src_data_len; 
    /* Length of destination data */ 
    le32 dst_data_len; 
    /* Starting point for cipher processing in source data */ 
    le32 cipher_start_src_offset; 
    /* Length of the source data that the cipher will be computed on */ 
    le32 len_to_cipher; 
    /* Starting point for hash processing in source data */ 
    le32 hash_start_src_offset; 
    /* Length of the source data that the hash will be computed on */ 
    le32 len_to_hash; 
    /* Length of the additional auth data */ 
    le32 aad_len; 
    /* Length of the hash result */ 
    le32 hash_result_len; 
    le32 reserved; 
}; 

struct virtio_crypto_alg_chain_data_vlf { 
    /* Device read only portion */ 
 
    /* Initialization Vector or Counter data */ 
    u8 iv[iv_len]; 
    /* Source data */ 
    u8 src_data[src_data_len]; 
    /* Additional authenticated data if exists */ 
    u8 aad[aad_len]; 
 
    /* Device write only portion */ 
 
    /* Destination data */ 
    u8 dst_data[dst_data_len]; 
    /* Hash result data */ 
    u8 hash_result[hash_result_len]; 
};
*/
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoAlgChainDataFlf {
    pub iv_len: u32,
    pub src_data_len: u32,
    pub dst_data_len: u32,
    pub cipher_start_src_offset: u32,
    pub len_to_cipher: u32,
    pub hash_start_src_offset: u32,
    pub len_to_hash: u32,
    pub aad_len: u32,
    pub hash_result_len: u32,
    pub reserved: u32,
}


// Symmetric Algorithms
/*
struct virtio_crypto_sym_data_flf { 
    /* Device read only portion */ 
 
#define VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE    40 
    u8 op_type_flf[VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE]; 
 
    /* See above VIRTIO_CRYPTO_SYM_OP_* */ 
    le32 op_type; 
    le32 padding; 
}; 
*/
pub const VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE: u32 = 40;
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoSymDataFlf {
    pub op_type_flf: [u8; VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE as usize],
    // Should be VirtioCryptoCipherDataFlf or VirtioCryptoAlgChainDataFlf
    pub op_type: u32,
    pub padding: u32,
}

impl VirtioCryptoSymDataFlf {
    pub fn new(op_type_flf: &[u8], op_type: u32) -> Self {
        let mut flf = [0; VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE as usize];
        let len = op_type_flf.len().min(VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE as usize);
        flf[..len].copy_from_slice(&op_type_flf[..len]);
        Self {
            op_type_flf: flf,
            op_type,
            padding: 0,
        }
    }
}

