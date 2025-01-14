use core::{hash, hint::spin_loop, ops::Sub, panic};

use bitflags::bitflags;
use alloc::vec;
use alloc::vec::Vec;
use ostd::{early_println, mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, VmIo}, Pod};
use crate::{alloc::string::ToString, device::crypto::{self, device::{CryptoDevice, SubmittedReq}, header::{VirtioCryptoCreateSessionInput, VirtioCryptoCtrlHeader, VirtioCryptoDestroySessionFlf, VirtioCryptoDestroySessionInput, VirtioCryptoInhdr, VirtioCryptoOpCtrlReqFlf, VirtioCryptoOpDataReq, VirtioCryptoOpHeader, VIRTIO_CRYPTO_AKCIPHER_DECRYPT, VIRTIO_CRYPTO_AKCIPHER_ENCRYPT, VIRTIO_CRYPTO_AKCIPHER_SIGN, VIRTIO_CRYPTO_AKCIPHER_VERIFY}}};
use alloc::string::String;

use super::services::VIRTIO_CRYPTO_SERVICE_AKCIPHER;

pub const VIRTIO_CRYPTO_NO_AKCIPHER: u32 = 0;
pub const VIRTIO_CRYPTO_AKCIPHER_RSA: u32 = 1;
pub const VIRTIO_CRYPTO_AKCIPHER_ECDSA: u32 = 2;

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

    pub const ENCRYPT: u32 = 1;
    pub const DECRYPT: u32 = 2;
    pub const SIGN: u32 = 3;
    pub const VERIFY: u32 = 4;

    pub fn send_create_session_rsa_request(device: &CryptoDevice, padding_algo: u32, hash_algo: u32, public_or_private: u32, key: &[u8]) -> (u32, u16) {
        
        let req_slice_size = VirtioCryptoOpCtrlReqFlf::SIZE + key.len();
        let req_slice_record = device.request_buffer_allocator.disable_irq().lock().allocate(req_slice_size).unwrap();
        
        let req_slice = {
            let req_slice = DmaStreamSlice::new(&device.request_buffer, req_slice_record.head, req_slice_size);
            let header = VirtioCryptoCtrlHeader::new(
                VIRTIO_CRYPTO_SERVICE_AKCIPHER, 
                VIRTIO_CRYPTO_AKCIPHER_RSA, 
                VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_CREATE_SESSION
            );
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
                VirtioCryptoAkcipherCreateSessionFlf::new(
                    VIRTIO_CRYPTO_AKCIPHER_RSA, 
                    key_type, 
                    key.len() as u32, 
                    rsa_session_para.as_bytes()
                )
            };

            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, op_flf.as_bytes());
            req_slice.write_val(0, &req_flf).unwrap();
            req_slice.write_bytes(VirtioCryptoOpCtrlReqFlf::SIZE, key).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };

        let resp_slice_size = VirtioCryptoCreateSessionInput::SIZE;
        let resp_slice_record = device.response_buffer_allocator.disable_irq().lock().allocate(resp_slice_size).unwrap();

        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(&device.response_buffer, resp_slice_record.head, resp_slice_size);
            resp_slice.write_val(0, &VirtioCryptoCreateSessionInput::default()).unwrap();
            resp_slice
        };

        let mut queue = device.controlq.disable_irq().lock();
        let token = queue.add_dma_buf(&[&req_slice], &[&resp_slice]).expect("add queue failed");
        if queue.should_notify() {
            queue.notify();
        }

        device.controlq_manager.disable_irq().lock().add(
            SubmittedReq::new(token, req_slice_record, resp_slice_record, false, 0)
        );

        (CryptoDevice::CONTROLQ, token)
    }

    pub fn create_session_rsa(device: &CryptoDevice, padding_algo: u32, hash_algo: u32, public_or_private: u32, key: &[u8]) -> u64 {
        let (queue_index, token) = Self::send_create_session_rsa_request(device, padding_algo, hash_algo, public_or_private, key);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
        resp.session_id
    }

    pub fn send_create_session_ecdsa_request(device: &CryptoDevice, curve_id: u32, public_or_private: u32, key: &[u8]) -> (u32, u16) {

        let req_slice_size = VirtioCryptoOpCtrlReqFlf::SIZE + key.len();
        let req_slice_record = device.request_buffer_allocator.disable_irq().lock().allocate(req_slice_size).unwrap();

        let req_slice = {
            let req_slice = DmaStreamSlice::new(&device.request_buffer, req_slice_record.head, req_slice_size);
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

            req_slice.write_val(0, &req_flf).unwrap();
            req_slice.write_bytes(VirtioCryptoOpCtrlReqFlf::SIZE, key).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };

        let resp_slice_size = VirtioCryptoCreateSessionInput::SIZE;
        let resp_slice_record = device.response_buffer_allocator.disable_irq().lock().allocate(resp_slice_size).unwrap();

        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(&device.response_buffer, resp_slice_record.head, resp_slice_size);
            resp_slice.write_val(0, &VirtioCryptoCreateSessionInput::default()).unwrap();
            resp_slice
        };

        let mut queue = device.controlq.disable_irq().lock();
        let token = queue.add_dma_buf(&[&req_slice], &[&resp_slice]).expect("add queue failed");
        if queue.should_notify() {
            queue.notify();
        }

        device.controlq_manager.disable_irq().lock().add(
            SubmittedReq::new(token, req_slice_record, resp_slice_record, false, 0)
        );

        (CryptoDevice::CONTROLQ, token)
    }

    pub fn create_session_ecdsa(device: &CryptoDevice, curve_id: u32, public_or_private: u32, key: &[u8]) -> u64 {
        let (queue_index, token) = Self::send_create_session_ecdsa_request(device, curve_id, public_or_private, key);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
        resp.session_id
    }

    pub fn send_destroy_session_request(device: &CryptoDevice, session_id: u64) -> (u32, u16) {

        let req_slice_size = VirtioCryptoOpCtrlReqFlf::SIZE;
        let req_slice_record = device.request_buffer_allocator.disable_irq().lock().allocate(req_slice_size).unwrap();

        let req_slice = {
            let req_slice = DmaStreamSlice::new(&device.request_buffer, req_slice_record.head, req_slice_size);
            let header = VirtioCryptoCtrlHeader::new(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0, VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_DESTROY_SESSION);
            let destroy_session_flf = VirtioCryptoDestroySessionFlf::new(session_id);
            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, destroy_session_flf.as_bytes());

            req_slice.write_val(0, &req_flf).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };

        let resp_slice_size = VirtioCryptoDestroySessionInput::SIZE;
        let resp_slice_record = device.response_buffer_allocator.disable_irq().lock().allocate(resp_slice_size).unwrap();
        
        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(&device.response_buffer, resp_slice_record.head, resp_slice_size);
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

        device.controlq_manager.disable_irq().lock().add(
            SubmittedReq::new(token, req_slice_record, resp_slice_record, false, 0)
        );

        (CryptoDevice::CONTROLQ, token)
    }

    fn destroy_session(device: &CryptoDevice, session_id: u64) {
        let (queue_index, token) = Self::send_destroy_session_request(device, session_id);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let resp: VirtioCryptoDestroySessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
    }

    pub fn send_encrypt_or_decrypt_or_sign_or_verify_request(device: &CryptoDevice, session_id: u64, algo: u32, op: u32, src_data: &Vec<u8>, dst_data_len: u32) -> (u32, u16) {
        
        let req_slice_size = VirtioCryptoOpDataReq::SIZE + src_data.len();
        let req_slice_record = device.request_buffer_allocator.disable_irq().lock().allocate(req_slice_size).unwrap();

        let req_slice = {
            let req_slice = DmaStreamSlice::new(&device.request_buffer, req_slice_record.head, req_slice_size);
            let opcode = match op {
                Self::ENCRYPT => VIRTIO_CRYPTO_AKCIPHER_ENCRYPT,
                Self::DECRYPT => VIRTIO_CRYPTO_AKCIPHER_DECRYPT,
                Self::SIGN => VIRTIO_CRYPTO_AKCIPHER_SIGN,
                Self::VERIFY => VIRTIO_CRYPTO_AKCIPHER_VERIFY,
                _ => panic!("invalid para: op"),
            };
            let header = VirtioCryptoOpHeader {
                opcode,
                algo,
                session_id,
                flag: 0,
                padding: 0,
            };

            let akcipher_data_flf = {
                let _dst_data_len = match op {
                    Self::ENCRYPT | Self::DECRYPT | Self::SIGN => dst_data_len,
                    Self::VERIFY => 0,
                    _ => panic!("invalid para: op"),
                };
                let akcipher_data_flf = VirtioCryptoAkcipherDataFlf {
                    src_data_len: src_data.len() as u32,
                    dst_data_len: _dst_data_len,
                };
                akcipher_data_flf.pad_to_48()
            };

            let data_req_flf = VirtioCryptoOpDataReq {
                header, 
                op_flf: akcipher_data_flf
            };

            req_slice.write_val(0, &data_req_flf).unwrap();
            req_slice.write_bytes(VirtioCryptoOpDataReq::SIZE, &src_data.as_slice()).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };

        let dst_data = vec![0; dst_data_len as usize];
        let inhdr = VirtioCryptoInhdr::default();

        let resp_slice_size = dst_data.len() + VirtioCryptoInhdr::SIZE as usize;
        let resp_slice_record = device.response_buffer_allocator.disable_irq().lock().allocate(resp_slice_size).unwrap();

        let resp_slice = {
            let combined_resp = [dst_data.as_slice(), inhdr.as_bytes()].concat();
            let resp_slice = DmaStreamSlice::new(&device.response_buffer, resp_slice_record.head, resp_slice_size);
            resp_slice.write_bytes(0, combined_resp.as_slice()).unwrap();
            resp_slice.sync().unwrap();
            resp_slice
        };

        let mut queue = device.dataqs[0].disable_irq().lock();
        let token = queue.add_dma_buf(&[&req_slice], &[&resp_slice]).expect("add queue failed");

        if queue.should_notify() {
            queue.notify();
        }

        device.dataq_manager.disable_irq().lock().add(
            SubmittedReq::new(token, req_slice_record, resp_slice_record, false, 0)
        );

        (CryptoDevice::DATAQ, token)
    }

    pub fn encrypt_or_decrypt_or_sign_or_verify(device: &CryptoDevice, session_id: u64, algo: u32, op: u32, src_data: &Vec<u8>, dst_data_len: u32) -> Vec<u8> {
        let (queue_index, token) = Self::send_encrypt_or_decrypt_or_sign_or_verify_request(device, session_id, algo, op, src_data, dst_data_len);
        let (resp_slice, dst_data_len_buf) = device.get_resp_slice_from(queue_index, token);
        early_println!("dst_data_len_buf: {:?}", dst_data_len_buf);
        resp_slice.sync().unwrap();
        let mut binding = vec![0 as u8; (dst_data_len_buf - 1) as usize];
        let dst_data = binding.as_mut_slice();
        resp_slice.read_bytes(0, dst_data).unwrap();
        early_println!("Data: {:X?}", dst_data);
        dst_data.to_vec()
    }
    
    pub fn akcipher(device: &CryptoDevice, padding_algo: u32, hash_algo: u32, public_or_private: u32, akcipher_key: &Vec<u8>, algo: u32, op: u32, src_data: &Vec<u8>) -> Vec<u8> {
        let session_id = Akcipher::create_session_rsa(&device, padding_algo, hash_algo, public_or_private, &akcipher_key);
        let dst_data_len: u32 = match hash_algo {
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_MD5 => 128,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_SHA1 => 160,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_SHA256 => 256,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_SHA512 => 512,
            _ => panic!("Unsupported hash algorithm."),
        };
        let dst_data = Akcipher::encrypt_or_decrypt_or_sign_or_verify(&device, session_id, algo, op, src_data, dst_data_len);
        Akcipher::destroy_session(&device, session_id);
        dst_data
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

    pub const VIRTIO_CRYPTO_RSA_NO_HASH: u32 = 0; // Only supported in RAW PADDING mode [ignored]
    pub const VIRTIO_CRYPTO_RSA_MD2: u32 = 1; // [unsupported]
    pub const VIRTIO_CRYPTO_RSA_MD3: u32 = 2; // [unsupported]
    pub const VIRTIO_CRYPTO_RSA_MD4: u32 = 3; // [unsupported]
    pub const VIRTIO_CRYPTO_RSA_MD5: u32 = 4;
    pub const VIRTIO_CRYPTO_RSA_SHA1: u32 = 5;
    pub const VIRTIO_CRYPTO_RSA_SHA256: u32 = 6;
    pub const VIRTIO_CRYPTO_RSA_SHA384: u32 = 7; // [unsupported]
    pub const VIRTIO_CRYPTO_RSA_SHA512: u32 = 8;
    pub const VIRTIO_CRYPTO_RSA_SHA224: u32 = 9; // [unsupported]
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


#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoAkcipherDataFlf {
    src_data_len: u32,
    dst_data_len: u32,
}

impl VirtioCryptoAkcipherDataFlf {
    pub const SIZE: usize = size_of::<Self>();
    pub fn pad_to_48(&self) -> [u8; 48] {
        let mut dst = [0; 48];
        let len = Self::SIZE;
        dst[..len].copy_from_slice(&self.as_bytes()[..len]);
        dst
    }
}

