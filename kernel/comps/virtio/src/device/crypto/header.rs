#![allow(unsafe_code)]
use ostd::Pod;
use crate::device::crypto::service::services::{
    VIRTIO_CRYPTO_SERVICE_CIPHER,
    VIRTIO_CRYPTO_SERVICE_HASH,
    VIRTIO_CRYPTO_SERVICE_MAC,
    VIRTIO_CRYPTO_SERVICE_AEAD,
    VIRTIO_CRYPTO_SERVICE_AKCIPHER,
};

use super::service::symalg::VirtioCryptoSymCreateSessionFlf;
// use core::mem;

// Operation Status
pub const VIRTIO_CRYPTO_OK: u32 = 0;
pub const VIRTIO_CRYPTO_ERR: u32 = 1;
pub const VIRTIO_CRYPTO_BADMSG: u32 = 2;
pub const VIRTIO_CRYPTO_NOTSUPP: u32 = 3;
pub const VIRTIO_CRYPTO_INVSESS: u32 = 4;
pub const VIRTIO_CRYPTO_NOSPC: u32 = 5;
pub const VIRTIO_CRYPTO_KEY_REJECTED: u32 = 6;
// TODO: 白皮书中存在VIRTIO_CRYPTO_MAX，但并未对其值和作用进行定义（见5.9.7.1）
pub const VIRTIO_CRYPTO_MAX: u32 = 7;
// 自定义NOT_READY，用于初始化resp_slice
pub const _VIRTIO_CRYPTO_NOTREADY: u32 = 8;

// Opcode Definition
const fn virtio_crypto_opcode(service: u32, op: u32) -> u32 {
    (service << 8) | op
}

pub const VIRTIO_CRYPTO_CIPHER_CREATE_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x02);
pub const VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x03);
pub const VIRTIO_CRYPTO_HASH_CREATE_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_HASH, 0x02);
pub const VIRTIO_CRYPTO_HASH_DESTROY_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_HASH, 0x03);
pub const VIRTIO_CRYPTO_MAC_CREATE_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_MAC, 0x02);
pub const VIRTIO_CRYPTO_MAC_DESTROY_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_MAC, 0x03);
pub const VIRTIO_CRYPTO_AEAD_CREATE_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x02);
pub const VIRTIO_CRYPTO_AEAD_DESTROY_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x03);
pub const VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x04);
pub const VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x05);

pub const VIRTIO_CRYPTO_CIPHER_ENCRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x00);
pub const VIRTIO_CRYPTO_CIPHER_DECRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x01);
pub const VIRTIO_CRYPTO_HASH: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_HASH, 0x00);
pub const VIRTIO_CRYPTO_MAC: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_MAC, 0x00);
pub const VIRTIO_CRYPTO_AEAD_ENCRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x00);
pub const VIRTIO_CRYPTO_AEAD_DECRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x01);
pub const VIRTIO_CRYPTO_AKCIPHER_ENCRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x00);
pub const VIRTIO_CRYPTO_AKCIPHER_DECRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x01);
pub const VIRTIO_CRYPTO_AKCIPHER_SIGN: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x02);
pub const VIRTIO_CRYPTO_AKCIPHER_VERIFY: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x03);

// Header for Controlq
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoCtrlHeader {
    pub opcode: u32,
    pub algo: u32,
    pub flag: u32,
    pub reserved: u32,
}

pub const VIRTIO_CRYPTO_CTRLQ_OP_SPEC_HDR_LEGACY: u32 = 56;
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoOpCtrlReqPartial {
    pub header: VirtioCryptoCtrlHeader,
    pub op_flf: VirtioCryptoSymCreateSessionFlf,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoCreateSessionInput {
    pub session_id: u64,
    pub status: u32,
    pub padding: u32,
}

impl VirtioCryptoCreateSessionInput {
    pub fn default() -> Self {
        Self {
            session_id: 0,
            status: _VIRTIO_CRYPTO_NOTREADY,
            padding: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoDestroySessionFlf {
    pub session_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoDestroySessionInput {
    pub status: u8,
}

// Header for Dataq
pub const VIRTIO_CRYPTO_FLAG_SESSION_MODE: u32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoOpHeader {
    pub algo: u32,
    pub session_id: u64,
    pub flag: u32,
    pub padding: u32,
}
