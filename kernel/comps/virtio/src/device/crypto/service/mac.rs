use alloc::{string::String, vec::Vec, vec};

use bitflags::bitflags;
use ostd::{early_println, mm::{DmaStreamSlice, VmIo}, Pod};

use crate::{alloc::string::ToString, device::crypto::{device::{CryptoDevice, SubmittedReq}, header::{VirtioCryptoCreateSessionInput, VirtioCryptoCtrlHeader, VirtioCryptoDestroySessionFlf, VirtioCryptoDestroySessionInput, VirtioCryptoInhdr, VirtioCryptoOpCtrlReqFlf, VirtioCryptoOpDataReq, VirtioCryptoOpHeader, VIRTIO_CRYPTO_HASH}, service::services::VIRTIO_CRYPTO_SERVICE_MAC}};

use super::hash::{VirtioCryptoHashCreateSessionFlf, VirtioCryptoHashDataFlf};

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

    pub fn get_hash_and_auth_len(algo: u32) -> (u32, u32) {
        match algo {
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
        }
    }

    pub fn new(algo: u32) -> Self {
        let (hash_result_len, auth_key_len) = Self::get_hash_and_auth_len(algo);
        Self {
            algo,
            hash_result_len,
            auth_key_len,
            padding: 0,
        }
    }
}

pub struct Mac {

}

impl Mac {
    pub fn send_create_session_request(
        device: &CryptoDevice,
        algo: u32,
        auth_key: &[u8],
    ) -> (u32, u16) {
        // TODO_RAY: 检查service和algo的合法性

        let (hash_result_len, auth_key_len) = VirtioCryptoMacCreateSessionFlf::get_hash_and_auth_len(algo);
        assert_eq!(auth_key_len, auth_key.len() as u32, "auth_key_len inconsistent with algo");

        // 分配空间
        let req_size = VirtioCryptoOpCtrlReqFlf::SIZE + auth_key.len();
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
                VIRTIO_CRYPTO_SERVICE_MAC,
                algo,
                VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_CREATE_SESSION,
            );

            let op_flf = VirtioCryptoMacCreateSessionFlf::new(algo);

            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, op_flf.as_bytes());

            req_flf_slice.write_val(0, &req_flf).unwrap();
            req_flf_slice.sync().unwrap();
            req_flf_slice
        };

        let req_vlf_slice = {
            let req_vlf_slice = DmaStreamSlice::new(
                &device.request_buffer,
                req_slice_record.head + VirtioCryptoOpCtrlReqFlf::SIZE,
                auth_key.len(),
            );
            req_vlf_slice.write_bytes(0, auth_key).unwrap();
            req_vlf_slice
        };

        let req_slice_vec = vec![&req_flf_slice, &req_vlf_slice];

        let resp_size = VirtioCryptoCreateSessionInput::SIZE;
        let resp_slice_record = device
            .response_buffer_allocator
            .disable_irq()
            .lock()
            .allocate(resp_size)
            .unwrap();

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
            .add_dma_buf(req_slice_vec.as_slice(), &[&resp_slice])
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
                VIRTIO_CRYPTO_SERVICE_MAC,
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

    pub fn create_session(
        device: &CryptoDevice,
        algo: u32,
        auth_key: &[u8],
    ) -> u64 {
        let (queue_index, token) = Self::send_create_session_request(device, algo, auth_key);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwrap();
        resp.session_id
    }

    pub fn destroy_session(device: &CryptoDevice, session_id: u64) {
        let (queue_index, token) = Self::send_destroy_session_request(device, session_id);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        resp_slice.sync().unwrap();
        let _resp: VirtioCryptoDestroySessionInput = resp_slice.read_val(0).unwrap();
    }

    pub fn send_mac_request(device: &CryptoDevice, algo: u32, session_id: u64, src_data: &Vec<u8>) -> (u32, u16) {
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

    pub fn do_mac(device: &CryptoDevice, algo: u32, session_id: u64, src_data: &Vec<u8>) -> Vec<u8> {
        let (queue_index, token) = Self::send_mac_request(device, algo, session_id, src_data);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let mut binding = vec![0_u8; VirtioCryptoHashCreateSessionFlf::get_hash_result_len(algo) as usize];
        let result = binding.as_mut_slice();
        resp_slice.read_bytes(0, result).unwrap();
        early_println!("Data: {:X?}", result);
        result.to_vec()
    }

    pub fn mac(device: &CryptoDevice, algo: u32, auth_key: &[u8], src_data: &Vec<u8>) -> Vec<u8> {
        let session_id = Self::create_session(device, algo, auth_key);
        let dst_data = Self::do_mac(device, algo, session_id, src_data);
        Self::destroy_session(device, session_id);
        dst_data
    }
}