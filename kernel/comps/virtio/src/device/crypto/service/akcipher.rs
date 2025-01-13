use core::{hint::spin_loop, panic};

use bitflags::bitflags;
use alloc::vec;
use alloc::vec::Vec;
use ostd::{early_println, mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, VmIo}, Pod};
use crate::{alloc::string::ToString, device::crypto::{device::CryptoDevice, header::{VirtioCryptoCreateSessionInput, VirtioCryptoCtrlHeader, VirtioCryptoDestroySessionFlf, VirtioCryptoDestroySessionInput, VirtioCryptoOpCtrlReqFlf}}};
use alloc::string::String;

use super::services::VIRTIO_CRYPTO_SERVICE_AKCIPHER;

const VIRTIO_CRYPTO_NO_AKCIPHER: u32 = 0;
const VIRTIO_CRYPTO_AKCIPHER_RSA: u32 = 1;
const VIRTIO_CRYPTO_AKCIPHER_ECDSA: u32 = 2;

bitflags! {
    pub struct SupportedAkCiphers: u32 {
        const NO_AKCIPHER                  = 1 << VIRTIO_CRYPTO_NO_AKCIPHER;                   // 0x0001
        const RSA                          = 1 << VIRTIO_CRYPTO_AKCIPHER_RSA;                   // 0x0002
        const ECDSA                        = 1 << VIRTIO_CRYPTO_AKCIPHER_ECDSA;                 // 0x0004
    }
}

impl SupportedAkCiphers {
    pub fn from_u32(value: u32) -> Self {
        SupportedAkCiphers::from_bits_truncate(value)
    }

    pub fn get_supported_akciphers_name(&self) -> Vec<String> {
        let mut supported_akciphers_name = Vec::new();
        if self.contains(SupportedAkCiphers::NO_AKCIPHER) {
            supported_akciphers_name.push("No AKCipher".to_string());
        }
        if self.contains(SupportedAkCiphers::RSA) {
            supported_akciphers_name.push("RSA".to_string());
        }
        if self.contains(SupportedAkCiphers::ECDSA) {
            supported_akciphers_name.push("ECDSA".to_string());
        }
        supported_akciphers_name
    }
}

pub struct Akcipher {

}

impl Akcipher {
    pub const PUBLIC: u32 = 1;
    pub const PRIVATE: u32 = 2;

    pub fn create_session_rsa(device: &CryptoDevice, padding_algo: u32, hash_algo: u32, public_or_private: u32, key: &[u8]) -> u64 {
        let req_flf_slice = {
            let req_flf_slice = DmaStreamSlice::new(&device.request_buffer, 0, VirtioCryptoOpCtrlReqFlf::SIZE);
            let header = VirtioCryptoCtrlHeader::new(VIRTIO_CRYPTO_SERVICE_AKCIPHER, VIRTIO_CRYPTO_AKCIPHER_RSA, VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_CREATE_SESSION);
            let op_flf = {
                let key_type = match public_or_private {
                    Self::PUBLIC => VirtioCryptoAkcipherCreateSessionFlf::VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC,
                    Self::PRIVATE => VirtioCryptoAkcipherCreateSessionFlf::VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE,
                    _ => panic!("invalid para: public_or_private")
                };
                
                let rsa_session_para = VirtioCryptoRsaSessionPara {
                    padding_algo,
                    hash_algo,
                };

                VirtioCryptoAkcipherCreateSessionFlf::new(VIRTIO_CRYPTO_AKCIPHER_RSA, key_type, key.len() as u32, rsa_session_para.as_bytes())
            };

            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, op_flf.as_bytes());
            req_flf_slice.write_val(0, &req_flf).unwrap();
            req_flf_slice.sync().unwrap();
            req_flf_slice
        };

        let variable_length_data_stream = {
            let segment = FrameAllocOptions::new(1)
                .uninit(true)
                .alloc_contiguous()
                .unwrap();
            DmaStream::map(segment, DmaDirection::ToDevice, false).unwrap()
        };

        let req_vlf_slice = {
            let req_vlf_slice = DmaStreamSlice::new(&variable_length_data_stream, 0, key.len());
            req_vlf_slice.write_bytes(0, key).unwrap();
            req_vlf_slice
        };

        let req_slice_vec = vec![&req_flf_slice, &req_vlf_slice];

        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(&device.response_buffer, 0, VirtioCryptoCreateSessionInput::SIZE);
            resp_slice.write_val(0, &VirtioCryptoCreateSessionInput::default()).unwrap();
            resp_slice
        };

        let mut queue = device.controlq.disable_irq().lock();
        let token = queue.add_dma_buf(req_slice_vec.as_slice(), &[&resp_slice]).expect("add queue failed");
        if queue.should_notify() {
            queue.notify();
        }
        while !queue.can_pop() {
            spin_loop();
        }
        queue.pop_used_with_token(token).expect("pop used failed");
        resp_slice.sync().unwrap();
        let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
        resp.session_id
    }

    pub fn create_session_ecdsa(device: &CryptoDevice, curve_id: u32, public_or_private: u32, key: &[u8]) -> u64 {
        let req_flf_slice = {
            let req_flf_slice = DmaStreamSlice::new(&device.request_buffer, 0, VirtioCryptoOpCtrlReqFlf::SIZE);
            let header = VirtioCryptoCtrlHeader::new(VIRTIO_CRYPTO_SERVICE_AKCIPHER, VIRTIO_CRYPTO_AKCIPHER_ECDSA, VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_CREATE_SESSION);
            let op_flf = {
                let key_type = match public_or_private {
                    Self::PUBLIC => VirtioCryptoAkcipherCreateSessionFlf::VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC,
                    Self::PRIVATE => VirtioCryptoAkcipherCreateSessionFlf::VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE,
                    _ => panic!("invalid para: public_or_private")
                };
                
                let ecdsa_session_para = VirtioCryptoEcdsaSessionPara {
                    curve_id,
                };

                VirtioCryptoAkcipherCreateSessionFlf::new(VIRTIO_CRYPTO_AKCIPHER_ECDSA, key_type, key.len() as u32, ecdsa_session_para.as_bytes())
            };

            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, op_flf.as_bytes());
            req_flf_slice.write_val(0, &req_flf).unwrap();
            req_flf_slice.sync().unwrap();
            req_flf_slice
        };

        let variable_length_data_stream = {
            let segment = FrameAllocOptions::new(1)
                .uninit(true)
                .alloc_contiguous()
                .unwrap();
            DmaStream::map(segment, DmaDirection::ToDevice, false).unwrap()
        };

        let req_vlf_slice = {
            let req_vlf_slice = DmaStreamSlice::new(&variable_length_data_stream, 0, key.len());
            req_vlf_slice.write_bytes(0, key).unwrap();
            req_vlf_slice
        };

        let req_slice_vec = vec![&req_flf_slice, &req_vlf_slice];

        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(&device.response_buffer, 0, VirtioCryptoCreateSessionInput::SIZE);
            resp_slice.write_val(0, &VirtioCryptoCreateSessionInput::default()).unwrap();
            resp_slice
        };

        let mut queue = device.controlq.disable_irq().lock();
        let token = queue.add_dma_buf(req_slice_vec.as_slice(), &[&resp_slice]).expect("add queue failed");
        if queue.should_notify() {
            queue.notify();
        }
        while !queue.can_pop() {
            spin_loop();
        }
        queue.pop_used_with_token(token).expect("pop used failed");
        resp_slice.sync().unwrap();
        let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
        resp.session_id
    }

    pub fn destroy_session(device: &CryptoDevice, session_id: u64) {

        let req_slice = {
            let req_slice = DmaStreamSlice::new(&device.request_buffer, 0, VirtioCryptoOpCtrlReqFlf::SIZE);
            let header = VirtioCryptoCtrlHeader::new(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0, VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_DESTROY_SESSION);
            let destroy_session_flf = VirtioCryptoDestroySessionFlf::new(session_id);
            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, destroy_session_flf.as_bytes());

            req_slice.write_val(0, &req_flf).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };
        
        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(&device.response_buffer, 0, VirtioCryptoDestroySessionInput::SIZE);
            resp_slice
                .write_val(0, &VirtioCryptoDestroySessionInput::default())
                .unwrap();
            resp_slice
        };

        let mut queue = device.controlq.disable_irq().lock();
    
        let token = queue
            .add_dma_buf(&[&req_slice], &[&resp_slice])
            .expect("add queue failed");
        
        if queue.should_notify() {
            queue.notify();
        }

        while !queue.can_pop() {
            spin_loop();
        }
        queue.pop_used_with_token(token).expect("pop used failed");
        
        resp_slice.sync().unwrap();
        let resp: VirtioCryptoDestroySessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct VirtioCryptoAkcipherCreateSessionFlf {
    algo: u32,
    key_type: u32,
    key_len: u32,
    algo_flf: [u8; Self::VIRTIO_CRYPTO_AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE],
}

impl VirtioCryptoAkcipherCreateSessionFlf {
    const VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC: u32 = 1;
    const VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE: u32 = 2;
    const VIRTIO_CRYPTO_AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE: usize = 44;

    pub fn new(algo: u32, key_type: u32, key_len: u32, algo_flf: &[u8]) -> Self {
        let mut flf = [0; Self::VIRTIO_CRYPTO_AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE];
        let len = algo_flf.len().min(Self::VIRTIO_CRYPTO_AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE);
        flf[..len].copy_from_slice(&algo_flf[..len]);
        Self {
            algo,
            key_type,
            key_len,
            algo_flf: flf,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoRsaSessionPara {
    padding_algo: u32,
    hash_algo: u32,
}

impl VirtioCryptoRsaSessionPara {
    pub const VIRTIO_CRYPTO_RSA_RAW_PADDING: u32 = 0;
    pub const VIRTIO_CRYPTO_RSA_PKCS1_PADDING: u32 = 1;

    pub const VIRTIO_CRYPTO_RSA_NO_HASH: u32 = 0;
    pub const VIRTIO_CRYPTO_RSA_MD2: u32 = 1;
    pub const VIRTIO_CRYPTO_RSA_MD3: u32 = 2;
    pub const VIRTIO_CRYPTO_RSA_MD4: u32 = 3;
    pub const VIRTIO_CRYPTO_RSA_MD5: u32 = 4;
    pub const VIRTIO_CRYPTO_RSA_SHA1: u32 = 5;
    pub const VIRTIO_CRYPTO_RSA_SHA256: u32 = 6;
    pub const VIRTIO_CRYPTO_RSA_SHA384: u32 = 7;
    pub const VIRTIO_CRYPTO_RSA_SHA512: u32 = 8;
    pub const VIRTIO_CRYPTO_RSA_SHA224: u32 = 9;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoEcdsaSessionPara {
    curve_id: u32,
}

impl VirtioCryptoEcdsaSessionPara {
    pub const VIRTIO_CRYPTO_CURVE_UNKNOWN: u32 = 0;
    pub const VIRTIO_CRYPTO_CURVE_NIST_P192: u32 = 1;
    pub const VIRTIO_CRYPTO_CURVE_NIST_P224: u32 = 2;
    pub const VIRTIO_CRYPTO_CURVE_NIST_P256: u32 = 3;
    pub const VIRTIO_CRYPTO_CURVE_NIST_P384: u32 = 4;
    pub const VIRTIO_CRYPTO_CURVE_NIST_P521: u32 = 5;
}

