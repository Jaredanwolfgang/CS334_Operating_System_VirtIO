#![allow(unsafe_code)]
use core::panic;

use ostd::Pod;

use crate::device::crypto::service::services::{
    VIRTIO_CRYPTO_SERVICE_AEAD, VIRTIO_CRYPTO_SERVICE_AKCIPHER, VIRTIO_CRYPTO_SERVICE_CIPHER,
    VIRTIO_CRYPTO_SERVICE_HASH, VIRTIO_CRYPTO_SERVICE_MAC,
};
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

// OPCODE for ControlQ
pub const VIRTIO_CRYPTO_CIPHER_CREATE_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x02); // 2
pub const VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x03); // 3
pub const VIRTIO_CRYPTO_HASH_CREATE_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_HASH, 0x02); // 258
pub const VIRTIO_CRYPTO_HASH_DESTROY_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_HASH, 0x03); // 259
pub const VIRTIO_CRYPTO_MAC_CREATE_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_MAC, 0x02); // 514
pub const VIRTIO_CRYPTO_MAC_DESTROY_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_MAC, 0x03); // 515
pub const VIRTIO_CRYPTO_AEAD_CREATE_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x02); // 770
pub const VIRTIO_CRYPTO_AEAD_DESTROY_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x03); // 771
pub const VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x04); // 1028
pub const VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x05); // 1029

// OPCODE for DataQ
pub const VIRTIO_CRYPTO_CIPHER_ENCRYPT: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x00); // 0
pub const VIRTIO_CRYPTO_CIPHER_DECRYPT: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x01); // 1
pub const VIRTIO_CRYPTO_HASH: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_HASH, 0x00); // 256
pub const VIRTIO_CRYPTO_MAC: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_MAC, 0x00); // 512
pub const VIRTIO_CRYPTO_AEAD_ENCRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x00); // 768
pub const VIRTIO_CRYPTO_AEAD_DECRYPT: u32 = virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AEAD, 0x01); // 769
pub const VIRTIO_CRYPTO_AKCIPHER_ENCRYPT: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x00); // 1024
pub const VIRTIO_CRYPTO_AKCIPHER_DECRYPT: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x01); // 1025
pub const VIRTIO_CRYPTO_AKCIPHER_SIGN: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x02); // 1026
pub const VIRTIO_CRYPTO_AKCIPHER_VERIFY: u32 =
    virtio_crypto_opcode(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x03); // 1027

// Header for Controlq
/*

struct virtio_crypto_ctrl_header {
#define VIRTIO_CRYPTO_CIPHER_CREATE_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x02)
#define VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x03)
#define VIRTIO_CRYPTO_HASH_CREATE_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x02)
#define VIRTIO_CRYPTO_HASH_DESTROY_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x03)
#define VIRTIO_CRYPTO_MAC_CREATE_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x02)
#define VIRTIO_CRYPTO_MAC_DESTROY_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x03)
#define VIRTIO_CRYPTO_AEAD_CREATE_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x02)
#define VIRTIO_CRYPTO_AEAD_DESTROY_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x03)
#define VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION '  VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x04)
#define VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION '  VIRTIO_CRYPTO_OPCDE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x05)
    le32 opcode;
    /* algo should be service-specific algorithms */
    le32 algo;
    le32 flag;
    le32 reserved;
};
*/
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoCtrlHeader {
    pub opcode: u32,
    pub algo: u32,
    pub flag: u32,
    pub reserved: u32,
}

impl VirtioCryptoCtrlHeader {
    pub const VIRTIO_CRYPTO_CREATE_SESSION: u32 = 0;
    pub const VIRTIO_CRYPTO_DESTROY_SESSION: u32 = 1;

    pub fn new(service: u32, algo: u32, op: u32) -> VirtioCryptoCtrlHeader {
        let opcode = match service {
            VIRTIO_CRYPTO_SERVICE_CIPHER => match op {
                Self::VIRTIO_CRYPTO_CREATE_SESSION => VIRTIO_CRYPTO_CIPHER_CREATE_SESSION,
                Self::VIRTIO_CRYPTO_DESTROY_SESSION => VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION,
                _ => panic!("[virtio-crypto unsupported ctrl opcode]"),
            },
            VIRTIO_CRYPTO_SERVICE_HASH => match op {
                Self::VIRTIO_CRYPTO_DESTROY_SESSION => VIRTIO_CRYPTO_HASH_DESTROY_SESSION,
                _ => panic!("[virtio-crypto unsupported ctrl opcode]"),
            },
            VIRTIO_CRYPTO_SERVICE_MAC => match op {
                Self::VIRTIO_CRYPTO_DESTROY_SESSION => VIRTIO_CRYPTO_MAC_DESTROY_SESSION,
                _ => panic!("[virtio-crypto unsupported ctrl opcode]"),
            },
            VIRTIO_CRYPTO_SERVICE_AEAD => match op {
                Self::VIRTIO_CRYPTO_DESTROY_SESSION => VIRTIO_CRYPTO_AEAD_DESTROY_SESSION,
                _ => panic!("[virtio-crypto unsupported ctrl opcode]"),
            },
            VIRTIO_CRYPTO_SERVICE_AKCIPHER => match op {
                Self::VIRTIO_CRYPTO_CREATE_SESSION => VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION,
                Self::VIRTIO_CRYPTO_DESTROY_SESSION => VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION,
                _ => panic!("[virtio-crypto unsupported ctrl opcode]"),
            },
            _ => panic!("no such service"),
        };

        VirtioCryptoCtrlHeader {
            opcode,
            algo,
            flag: 0,
            reserved: 0,
        }
    }
}

/*
struct virtio_crypto_op_ctrl_req {
    /* Device read only portion */

    struct virtio_crypto_ctrl_header header;

#define VIRTIO_CRYPTO_CTRLQ_OP_SPEC_HDR_LEGACY 56
    /* fixed length fields, opcode specific */
    u8 op_flf[flf_len];

    /* variable length fields, opcode specific */
    u8 op_vlf[vlf_len];

    /* Device write only portion */

    /* op result or completion status */
    u8 op_outcome[outcome_len];
};
The request is composed of:
- A VirtioCryptoCtrlHeader
- A fixed length field (flf) of 56 bytes (Determined by the OPCODE in the header) (Padded to 56 bytes if not negotiated)
    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION -> virtio_crypto_sym_create_session_flf
    VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION -> virtio_crypto_akcipher_create_session_flf
    VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION | VIRTIO_CRYPTO_HASH_DESTROY_SESSION | VIRTIO_CRYPTO_MAC_DESTROY_SESSION | VIRTIO_CRYPTO_AEAD_DESTROY_SESSION | VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION
        -> virtio_crypto_destroy_session_flf
    _ -> [virtio-crypto unsupported ctrl opcode]
- A variable length field (vlf)
    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION -> virtio_crypto_sym_create_session_vlf
    VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION -> virtio_crypto_akcipher_create_session_vlf
    VIRTIO_CRYPTO_MAC_CREATE_SESSION | VIRTIO_CRYPTO_AEAD_CREATE_SESSION -> [virtio-crypto unsupported ctrl opcode]
    _ -> empty
- OP_OUTCOME
    *_CREATE_SESSION -> virtio_crypto_create_session_input
    *_DESTROY_SESSION -> virtio_crypto_destroy_session_input
*/
pub const VIRTIO_CRYPTO_CTRLQ_OP_SPEC_HDR_LEGACY: u32 = 56;
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoOpCtrlReqFlf {
    pub header: VirtioCryptoCtrlHeader,
    pub op_flf: [u8; VIRTIO_CRYPTO_CTRLQ_OP_SPEC_HDR_LEGACY as usize],
}

impl VirtioCryptoOpCtrlReqFlf {
    pub const SIZE: usize = size_of::<Self>();
    pub fn new(header: VirtioCryptoCtrlHeader, op_flf_bytes_slice: &[u8]) -> Self {
        let mut op_flf_bytes = [0; VIRTIO_CRYPTO_CTRLQ_OP_SPEC_HDR_LEGACY as usize];
        op_flf_bytes[..op_flf_bytes_slice.len()].copy_from_slice(op_flf_bytes_slice);
        Self {
            header,
            op_flf: op_flf_bytes,
        }
    }
}

// virtio_crypto_create_session_input
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoCreateSessionInput {
    pub session_id: u64,
    pub status: u32,
    pub padding: u32,
}

impl Default for VirtioCryptoCreateSessionInput {
    fn default() -> Self {
        Self {
            session_id: 0,
            status: _VIRTIO_CRYPTO_NOTREADY,
            padding: 0,
        }
    }
}

impl VirtioCryptoCreateSessionInput {
    pub const SIZE: usize = size_of::<Self>();
}

// virtio_crypto_destroy_session_flf
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoDestroySessionFlf {
    pub session_id: u64,
}

impl VirtioCryptoDestroySessionFlf {
    pub fn new(session_id: u64) -> Self {
        Self { session_id }
    }
}

// virtio_crypto_destroy_session_input
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoDestroySessionInput {
    pub status: u8,
}

impl Default for VirtioCryptoDestroySessionInput {
    fn default() -> Self {
        Self {
            status: _VIRTIO_CRYPTO_NOTREADY as u8,
        }
    }
}

impl VirtioCryptoDestroySessionInput {
    pub const SIZE: usize = size_of::<Self>();
}

// Header for Dataq
/*
struct virtio_crypto_op_header {
#define VIRTIO_CRYPTO_CIPHER_ENCRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x00)
#define VIRTIO_CRYPTO_CIPHER_DECRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x01)
#define VIRTIO_CRYPTO_HASH VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x00)
#define VIRTIO_CRYPTO_MAC VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x00)
#define VIRTIO_CRYPTO_AEAD_ENCRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x00)
#define VIRTIO_CRYPTO_AEAD_DECRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x01)
#define VIRTIO_CRYPTO_AKCIPHER_ENCRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x00)
#define VIRTIO_CRYPTO_AKCIPHER_DECRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x01)
#define VIRTIO_CRYPTO_AKCIPHER_SIGN VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x02)
#define VIRTIO_CRYPTO_AKCIPHER_VERIFY VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x03)
    le32 opcode;
    /* algo should be service-specific algorithms */
    le32 algo;
    le64 session_id;
#define VIRTIO_CRYPTO_FLAG_SESSION_MODE 1
    /* control flag to control the request */
    le32 flag;
    le32 padding;
};
Note:
- If VIRTIO_CRYPTO_F_REVISION_1 is not negotiated the flag is ignored.
- If VIRTIO_CRYPTO_F_REVISION_1 is negotiated but VIRTIO_CRYPTO_F_STATELESS_MODE is not negotiated,
then the device SHOULD reject requests if VIRTIO_CRYPTO_FLAG_SESSION_MODE is not set (in flag).
*/
pub const VIRTIO_CRYPTO_FLAG_SESSION_MODE: u32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoOpHeader {
    pub opcode: u32,
    pub algo: u32,
    pub session_id: u64,
    pub flag: u32,
    pub padding: u32,
}

/*
struct virtio_crypto_op_data_req {
    /* Device read only portion */

    struct virtio_crypto_op_header header;

#define VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY 48
    /* fixed length fields, opcode specific */
    u8 op_flf[flf_len];

    /* Device read && write portion */
    /* variable length fields, opcode specific */
    u8 op_vlf[vlf_len];

    /* Device write only portion */
    struct virtio_crypto_inhdr inhdr;
};
The request is composed of:
- A VirtioCryptoOpHeader
- A fixed length field (flf) of 48 bytes (Determined by the OPCODE in the header) (Padded to 48 bytes if not negotiated)
    VIRTIO_CRYPTO_CIPHER_ENCRYPT | VIRTIO_CRYPTO_CIPHER_DECRYPT ->
        VIRTIO_CRYPTO_F_CIPHER_STATELESS_MODE negotiated -> virtio_crypto_sym_data_flf_stateless
        VIRTIO_CRYPTO_F_CIPHER_STATELESS_MODE not negotiated -> virtio_crypto_sym_data_flf
    VIRTIO_CRYPTO_AKCIPHER_ENCRYPT | VIRTIO_CRYPTO_AKCIPHER_DECRYPT | VIRTIO_CRYPTO_AKCIPHER_SIGN | VIRTIO_CRYPTO_AKCIPHER_VERIFY ->
        VIRTIO_CRYPTO_F_AKCIPHER_STATELESS_MODE negotiated -> virtio_crypto_akcipher_data_flf_stateless
        VIRTIO_CRYPTO_F_AKCIPHER_STATELESS_MODE not negotiated -> virtio_crypto_akcipher_data_flf
    _ -> [virtio-crypto unsupported dataq opcode]
- A variable length field (vlf)
    VIRTIO_CRYPTO_CIPHER_ENCRYPT | VIRTIO_CRYPTO_CIPHER_DECRYPT ->
        VIRTIO_CRYPTO_F_CIPHER_STATELESS_MODE negotiated -> virtio_crypto_sym_data_vlf_stateless
        VIRTIO_CRYPTO_F_CIPHER_STATELESS_MODE not negotiated -> virtio_crypto_sym_data_vlf
    VIRTIO_CRYPTO_AKCIPHER_ENCRYPT | VIRTIO_CRYPTO_AKCIPHER_DECRYPT | VIRTIO_CRYPTO_AKCIPHER_SIGN | VIRTIO_CRYPTO_AKCIPHER_VERIFY ->
        VIRTIO_CRYPTO_F_AKCIPHER_STATELESS_MODE negotiated -> virtio_crypto_akcipher_data_vlf_stateless
        VIRTIO_CRYPTO_F_AKCIPHER_STATELESS_MODE not negotiated -> virtio_crypto_akcipher_data_vlf
    _ -> [virtio-crypto unsupported dataq opcode]
*/
pub const VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY: u32 = 48;
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoOpDataReq {
    pub header: VirtioCryptoOpHeader,
    pub op_flf: [u8; VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY as usize],
}

impl VirtioCryptoOpDataReq {
    pub const SIZE: usize = size_of::<VirtioCryptoOpDataReq>();
    pub fn new(header: VirtioCryptoOpHeader, op_flf: &[u8]) -> Self {
        let mut op_flf_bytes = [0; VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY as usize];
        op_flf_bytes[..op_flf.len()].copy_from_slice(op_flf);
        Self {
            header,
            op_flf: op_flf_bytes,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Default)]
pub struct VirtioCryptoInhdr {
    pub status: u8,
}

impl VirtioCryptoInhdr {
    pub const SIZE: u32 = size_of::<Self>() as u32;
}
