use alloc::{string::String, vec, vec::Vec};

use bitflags::bitflags;
use ostd::{early_println, mm::{DmaStreamSlice, VmIo}, Pod};

use crate::{alloc::string::ToString, device::crypto::{device::{CryptoDevice, SubmittedReq}, header::{VirtioCryptoCreateSessionInput, VirtioCryptoCtrlHeader, VirtioCryptoDestroySessionFlf, VirtioCryptoDestroySessionInput, VirtioCryptoInhdr, VirtioCryptoOpCtrlReqFlf, VirtioCryptoOpDataReq, VirtioCryptoOpHeader, VIRTIO_CRYPTO_HASH}}};

use super::services::VIRTIO_CRYPTO_SERVICE_HASH;

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

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoHashCreateSessionFlf {
    pub algo: u32,
    pub hash_result_len: u32,
}

impl Default for VirtioCryptoHashCreateSessionFlf {
    fn default() -> Self {
        Self {
            algo: VIRTIO_CRYPTO_HASH_SHA1,
            hash_result_len: 20,
        }
    }
}

impl VirtioCryptoHashCreateSessionFlf {

    const VIRTIO_CRYPTO_HASH_SESS_OP_SPEC_HDR_SIZE: usize = 56;

    pub fn get_hash_result_len(algo: u32) -> u32 {
        match algo {
            VIRTIO_CRYPTO_HASH_MD5 => 16,
            VIRTIO_CRYPTO_HASH_SHA1 => 20,
            VIRTIO_CRYPTO_HASH_SHA_224 => 28,
            VIRTIO_CRYPTO_HASH_SHA_256 => 32,
            VIRTIO_CRYPTO_HASH_SHA_384 => 48,
            VIRTIO_CRYPTO_HASH_SHA_512 => 64,
            VIRTIO_CRYPTO_HASH_SHA3_224 => 28,
            VIRTIO_CRYPTO_HASH_SHA3_256 => 32,
            VIRTIO_CRYPTO_HASH_SHA3_384 => 48,
            VIRTIO_CRYPTO_HASH_SHA3_512 => 64,
            VIRTIO_CRYPTO_HASH_SHA3_SHAKE128 => 16,
            VIRTIO_CRYPTO_HASH_SHA3_SHAKE256 => 32,
            _ => 0,
        }
    }

    pub fn new(algo: u32) -> Self {
        let hash_result_len = Self::get_hash_result_len(algo);
        Self {
            algo,
            hash_result_len,
        }
    }

    pub fn to_padded_bytes(&self) -> [u8; Self::VIRTIO_CRYPTO_HASH_SESS_OP_SPEC_HDR_SIZE] {
        let mut flf = [0; Self::VIRTIO_CRYPTO_HASH_SESS_OP_SPEC_HDR_SIZE];
        let len = size_of::<Self>().min(Self::VIRTIO_CRYPTO_HASH_SESS_OP_SPEC_HDR_SIZE as usize);
        flf[..len].copy_from_slice(&self.as_bytes()[..len]);
        flf
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoHashDataFlf {
    src_data_len: u32,
    hash_result_len: u32,
}

impl VirtioCryptoHashDataFlf {
    const VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY: usize = 48;

    pub fn new(src_data_len: u32, algo: u32) -> Self {
        Self {
            src_data_len,
            hash_result_len: VirtioCryptoHashCreateSessionFlf::get_hash_result_len(algo)
        }
    }

    pub fn to_padded_bytes(&self) -> [u8; Self::VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY] {
        let mut flf = [0; Self::VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY];
        let len = size_of::<Self>().min(Self::VIRTIO_CRYPTO_DATAQ_OP_SPEC_HDR_LEGACY);
        flf[..len].copy_from_slice(&self.as_bytes()[..len]);
        flf
    }
}

pub struct Hash {

}

impl Hash {
    pub fn send_create_session_request(
        device: &CryptoDevice,
        algo: u32
    ) -> (u32, u16) {
        // TODO_RAY: 检查service和algo的合法性

        // 分配空间
        let req_size = VirtioCryptoOpCtrlReqFlf::SIZE;
        let req_slice_record = device
            .request_buffer_allocator
            .disable_irq()
            .lock()
            .allocate(req_size)
            .unwrap();

        let req_flf_slice = {
            let req_flf_slice = DmaStreamSlice::new(
                &device.request_buffer,
                req_slice_record.head,
                VirtioCryptoOpCtrlReqFlf::SIZE,
            );

            let header = VirtioCryptoCtrlHeader::new(
                VIRTIO_CRYPTO_SERVICE_HASH,
                algo,
                VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_CREATE_SESSION,
            );

            let op_flf = {
                VirtioCryptoHashCreateSessionFlf::new(algo).to_padded_bytes()
            };

            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, op_flf.as_bytes());

            req_flf_slice.write_val(0, &req_flf).unwrap();
            req_flf_slice.sync().unwrap();
            req_flf_slice
        };

        let resp_slice_size = VirtioCryptoCreateSessionInput::SIZE;
        let resp_slice_record = device.response_buffer_allocator.disable_irq().lock().allocate(resp_slice_size).unwrap();

        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(
                &device.response_buffer,
                resp_slice_record.head,
                VirtioCryptoCreateSessionInput::SIZE,
            );
            resp_slice
                .write_val(0, &VirtioCryptoCreateSessionInput::default())
                .unwrap();
            resp_slice
        };

        let mut queue = device.controlq.disable_irq().lock();

        let token = queue
            .add_dma_buf(&[&req_flf_slice], &[&resp_slice])
            .expect("add queue failed");

        device
            .controlq_manager
            .disable_irq()
            .lock()
            .add(SubmittedReq::new(
                token,
                req_slice_record,
                resp_slice_record,
                false,
                0,
            ));

        if queue.should_notify() {
            queue.notify();
        }

        (CryptoDevice::CONTROLQ, token)
    }

    pub fn create_session(
        device: &CryptoDevice,
        algo: u32
    ) -> u64 {
        let (queue_index, token) =
            Hash::send_create_session_request(device, algo);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwrap();
        early_println!("{:?}", resp);
        resp.session_id
    }

    pub fn send_destroy_session_request(device: &CryptoDevice, session_id: u64) -> (u32, u16) {
        // TODO_RAY: 检查service和algo的合法性

        let req_slice_size = VirtioCryptoOpCtrlReqFlf::SIZE;
        let req_slice_record = device
            .request_buffer_allocator
            .disable_irq()
            .lock()
            .allocate(req_slice_size)
            .unwrap();

        let req_slice = {
            let req_slice = DmaStreamSlice::new(
                &device.request_buffer,
                req_slice_record.head,
                VirtioCryptoOpCtrlReqFlf::SIZE,
            );
            let header = VirtioCryptoCtrlHeader::new(
                VIRTIO_CRYPTO_SERVICE_HASH,
                0,
                VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_DESTROY_SESSION,
            );
            let destroy_session_flf = VirtioCryptoDestroySessionFlf::new(session_id);
            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, destroy_session_flf.as_bytes());

            req_slice.write_val(0, &req_flf).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };

        let resp_slice_size = VirtioCryptoDestroySessionInput::SIZE;
        let resp_slice_record = device
            .response_buffer_allocator
            .disable_irq()
            .lock()
            .allocate(resp_slice_size)
            .unwrap();

        let resp_slice = {
            let resp_slice = DmaStreamSlice::new(
                &device.response_buffer,
                resp_slice_record.head,
                VirtioCryptoDestroySessionInput::SIZE,
            );
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

        device
            .controlq_manager
            .disable_irq()
            .lock()
            .add(SubmittedReq::new(
                token,
                req_slice_record,
                resp_slice_record,
                false,
                0,
            ));

        (CryptoDevice::CONTROLQ, token)
    }

    pub fn destroy_session(device: &CryptoDevice, session_id: u64) {
        let (queue_index, token) = Hash::send_destroy_session_request(device, session_id);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        resp_slice.sync().unwrap();
        let resp: VirtioCryptoDestroySessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
    }

    pub fn send_hash_request(device: &CryptoDevice, algo: u32, session_id: u64, src_data: &Vec<u8>) -> (u32, u16) {
        let req_slice_size = VirtioCryptoOpDataReq::SIZE + src_data.len();
        let req_slice_record = device
            .request_buffer_allocator
            .disable_irq()
            .lock()
            .allocate(req_slice_size)
            .unwrap();

        let req_slice = {

            let opcode = VIRTIO_CRYPTO_HASH;

            let header = VirtioCryptoOpHeader {
                opcode,
                algo,
                session_id,
                flag: 0,
                padding: 0,
            };

            let hash_data_flf = VirtioCryptoHashDataFlf::new(src_data.len() as u32, algo);
            let crypto_req = VirtioCryptoOpDataReq::new(header, hash_data_flf.as_bytes());
            let combined_req = [crypto_req.as_bytes(), src_data.as_slice()].concat();

            let req_slice = DmaStreamSlice::new(
                &device.request_buffer,
                req_slice_record.head,
                req_slice_size,
            );
            req_slice.write_bytes(0, combined_req.as_slice()).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };

        let dst_data = vec![0; VirtioCryptoHashCreateSessionFlf::get_hash_result_len(algo) as usize];
        let inhdr = VirtioCryptoInhdr::default();

        let resp_slice_size = dst_data.len() + VirtioCryptoInhdr::SIZE as usize;
        let resp_slice_record = device
            .response_buffer_allocator
            .disable_irq()
            .lock()
            .allocate(resp_slice_size)
            .unwrap();

        let resp_slice = {
            let combined_resp = [dst_data.as_slice(), inhdr.as_bytes()].concat();

            let resp_slice = DmaStreamSlice::new(
                &device.response_buffer,
                resp_slice_record.head,
                resp_slice_size,
            );
            resp_slice.write_bytes(0, combined_resp.as_slice()).unwrap();
            resp_slice
        };

        let mut queue = device.dataqs[0].disable_irq().lock();
        let token = queue
            .add_dma_buf(&[&req_slice], &[&resp_slice])
            .expect("add queue failed");

        if queue.should_notify() {
            queue.notify();
        }

        device
            .dataq_manager
            .disable_irq()
            .lock()
            .add(SubmittedReq::new(
                token,
                req_slice_record,
                resp_slice_record,
                false,
                0,
            ));

        (CryptoDevice::DATAQ, token)
    }

    pub fn do_hash(device: &CryptoDevice, algo: u32, session_id: u64, src_data: &Vec<u8>) -> Vec<u8> {
        let (queue_index, token) = Self::send_hash_request(device, algo, session_id, src_data);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let mut binding = vec![0_u8; VirtioCryptoHashCreateSessionFlf::get_hash_result_len(algo) as usize];
        let result = binding.as_mut_slice();
        resp_slice.read_bytes(0, result).unwrap();
        early_println!("Data: {:X?}", result);
        result.to_vec()
    }

    pub fn hash(device: &CryptoDevice, algo: u32, src_data: &Vec<u8>) -> Vec<u8> {
        let session_id = Self::create_session(device, algo);
        let dst_data = Self::do_hash(device, algo, session_id, src_data);
        Self::destroy_session(device, session_id);
        dst_data
    }
}