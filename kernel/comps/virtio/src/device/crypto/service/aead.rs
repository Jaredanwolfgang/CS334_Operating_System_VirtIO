use alloc::{string::String, vec::Vec, vec};

use bitflags::bitflags;
use ostd::{early_println, mm::{DmaStreamSlice, VmIo}, Pod};

use crate::{alloc::string::ToString, device::crypto::{device::{CryptoDevice, SubmittedReq}, header::{VirtioCryptoCreateSessionInput, VirtioCryptoCtrlHeader, VirtioCryptoDestroySessionFlf, VirtioCryptoDestroySessionInput, VirtioCryptoInhdr, VirtioCryptoOpCtrlReqFlf, VirtioCryptoOpDataReq, VirtioCryptoOpHeader, VIRTIO_CRYPTO_AEAD_DECRYPT, VIRTIO_CRYPTO_AEAD_ENCRYPT}}};

use super::{services::VIRTIO_CRYPTO_SERVICE_AEAD, sym::VirtioCryptoCipherSessionFlf};

const VIRTIO_CRYPTO_NO_AEAD: u32 = 0;
const VIRTIO_CRYPTO_AEAD_GCM: u32 = 1;
const VIRTIO_CRYPTO_AEAD_CCM: u32 = 2;
const VIRTIO_CRYPTO_AEAD_CHACHA20_POLY1305: u32 = 3;

bitflags! {
    pub struct SupportedAeads: u32 {
        const NO_AEAD                      = 1 << VIRTIO_CRYPTO_NO_AEAD;                      // 0x0001
        const GCM                          = 1 << VIRTIO_CRYPTO_AEAD_GCM;                      // 0x0002
        const CCM                          = 1 << VIRTIO_CRYPTO_AEAD_CCM;                      // 0x0004
        const CHACHA20_POLY1305            = 1 << VIRTIO_CRYPTO_AEAD_CHACHA20_POLY1305;        // 0x0008
    }
}

impl SupportedAeads {
    pub fn from_u32(value: u32) -> Self {
        SupportedAeads::from_bits_truncate(value)
    }

    pub fn get_supported_aeads_name(&self) -> Vec<String> {
        let mut supported_aeads_name = Vec::new();
        if self.contains(SupportedAeads::NO_AEAD) {
            supported_aeads_name.push("No AEAD".to_string());
        }
        if self.contains(SupportedAeads::GCM) {
            supported_aeads_name.push("GCM".to_string());
        }
        if self.contains(SupportedAeads::CCM) {
            supported_aeads_name.push("CCM".to_string());
        }
        if self.contains(SupportedAeads::CHACHA20_POLY1305) {
            supported_aeads_name.push("ChaCha20-Poly1305".to_string());
        }
        supported_aeads_name
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoAeadCreateSessionFlf {
    algo: u32,
    key_len: u32,
    tag_len: u32,
    aad_len: u32,
    op: u32,
    padding: u32,
}

impl VirtioCryptoAeadCreateSessionFlf {
    pub fn new(algo: u32, key_len: u32, tag_len: u32, aad_len: u32, op: u32) -> Self {
        Self {
            algo,
            key_len,
            tag_len,
            aad_len,
            op,
            padding: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct VirtioCryptoAeadDataFlf {
    iv_len: u32,
    aad_len: u32,
    src_data_len: u32,
    dst_data_len: u32,
    tag_len: u32,
    reserved: u32,
}

impl VirtioCryptoAeadDataFlf {
    pub fn new(iv_len: u32, aad_len: u32, src_data_len: u32, dst_data_len: u32, tag_len: u32) -> Self {
        Self {
            iv_len,
            aad_len,
            src_data_len,
            dst_data_len,
            tag_len,
            reserved: 0,
        }
    }
}

pub struct Aead {

}

impl Aead {

    pub const ENCRYPT: u32 = 1;
    pub const DECRYPT: u32 = 2;

    pub fn send_create_session_request(
        device: &CryptoDevice,
        algo: u32,
        encrypt_or_decrypt: u32,
        key: &[u8],
        tag_len: u32,
        aad_len: u32,
    ) -> (u32, u16) {
        // TODO_RAY: 检查service和algo的合法性

        // 分配空间
        let req_size = VirtioCryptoOpCtrlReqFlf::SIZE + key.len();
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
                VIRTIO_CRYPTO_SERVICE_AEAD,
                algo,
                VirtioCryptoCtrlHeader::VIRTIO_CRYPTO_CREATE_SESSION,
            );

            let op_flf = {
                let op = match encrypt_or_decrypt {
                    Self::ENCRYPT => VirtioCryptoCipherSessionFlf::VIRTIO_CRYPTO_OP_ENCRYPT,
                    Self::DECRYPT => VirtioCryptoCipherSessionFlf::VIRTIO_CRYPTO_OP_DECRYPT,
                    _ => panic!("invalid para: encrypt_or_decrypt"),
                };
                VirtioCryptoAeadCreateSessionFlf::new(algo, key.len() as u32, tag_len, aad_len, op)
            };

            let req_flf = VirtioCryptoOpCtrlReqFlf::new(header, op_flf.as_bytes());

            req_flf_slice.write_val(0, &req_flf).unwrap();
            req_flf_slice.sync().unwrap();
            req_flf_slice
        };

        let req_vlf_slice = {
            let req_vlf_slice = DmaStreamSlice::new(
                &device.request_buffer,
                req_slice_record.head + VirtioCryptoOpCtrlReqFlf::SIZE,
                key.len(),
            );
            req_vlf_slice.write_bytes(0, key).unwrap();
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
                VIRTIO_CRYPTO_SERVICE_AEAD,
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

    pub fn send_encrypt_or_decrypt_request(
        device: &CryptoDevice,
        algo: u32,
        session_id: u64,
        encrypt_or_decrypt: u32,
        iv: &[u8],
        aad: &[u8],
        src_data: &[u8],
        dst_data_len: u32,
        tag: &[u8],
    ) -> (u32, u16) {
        let req_slice_size = VirtioCryptoOpDataReq::SIZE + iv.len() + aad.len() + src_data.len();
        let req_slice_record = device
            .request_buffer_allocator
            .disable_irq()
            .lock()
            .allocate(req_slice_size)
            .unwrap();

        let req_slice = {
            let opcode = match encrypt_or_decrypt {
                Self::ENCRYPT => VIRTIO_CRYPTO_AEAD_ENCRYPT,
                Self::DECRYPT => VIRTIO_CRYPTO_AEAD_DECRYPT,
                _ => panic!("invalid para: encrypt_or_decrypt"),
            };
            let header = VirtioCryptoOpHeader {
                opcode,
                algo,
                session_id,
                flag: 0,
                padding: 0,
            };


            let aead_data_flf = VirtioCryptoAeadDataFlf::new(
                iv.len() as u32, 
                aad.len() as u32, 
                src_data.len() as u32, 
                dst_data_len, 
                tag.len() as u32
            );

            let crypto_req = VirtioCryptoOpDataReq::new(header, aead_data_flf.as_bytes());
            let combined_req = [crypto_req.as_bytes(), iv, src_data, aad].concat();

            let req_slice = DmaStreamSlice::new(
                &device.request_buffer,
                req_slice_record.head,
                req_slice_size,
            );
            req_slice.write_bytes(0, combined_req.as_slice()).unwrap();
            req_slice.sync().unwrap();
            req_slice
        };

        let dst_data = vec![0; dst_data_len as usize];
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

    pub fn create_session(
        device: &CryptoDevice,
        algo: u32,
        encrypt_or_decrypt: u32,
        key: &[u8],
        tag_len: u32,
        aad_len: u32
    ) -> u64 {
        let (queue_index, token) = Self::send_create_session_request(device, algo, encrypt_or_decrypt, key, tag_len, aad_len);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwrap();
        resp.session_id
    }

    pub fn encrypt_or_decrypt(
        device: &CryptoDevice,
        algo: u32,
        session_id: u64,
        encrypt_or_decrypt: u32,
        iv: &[u8],
        aad: &[u8],
        src_data: &[u8],
        dst_data_len: u32,
        tag: &[u8]
    ) -> Vec<u8> {
        let (queue_index, token) = Self::send_encrypt_or_decrypt_request(
            device,
            algo,
            session_id,
            encrypt_or_decrypt,
            iv,
            aad,
            src_data,
            dst_data_len,
            tag,
        );
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);

        let mut binding = vec![0_u8; dst_data_len as usize];
        let result = binding.as_mut_slice();
        resp_slice.read_bytes(0, result).unwrap();
        result.to_vec()
    }

    pub fn destroy_session(device: &CryptoDevice, session_id: u64) {
        let (queue_index, token) = Self::send_destroy_session_request(device, session_id);
        let (resp_slice, _write_len) = device.get_resp_slice_from(queue_index, token);
        resp_slice.sync().unwrap();
        let resp: VirtioCryptoDestroySessionInput = resp_slice.read_val(0).unwrap();
        early_println!("Status: {:?}", resp);
    }

    pub fn encrypt(
        device: &CryptoDevice,
        algo: u32,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        src_data: &[u8],
        dst_data_len: u32,
        tag: &[u8],
    ) -> Vec<u8> {
        let session_id = Self::create_session(device, algo, Self::ENCRYPT, key, tag.len() as u32, aad.len() as u32);
        let dst_data = Self::encrypt_or_decrypt(
            device,
            algo,
            session_id,
            Self::ENCRYPT,
            iv,
            aad,
            src_data,
            dst_data_len,
            tag,
        );
        Self::send_destroy_session_request(device, session_id);
        dst_data
    }

    pub fn decrypt(
        device: &CryptoDevice,
        algo: u32,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        src_data: &[u8],
        dst_data_len: u32,
        tag: &[u8],
    ) -> Vec<u8> {
        let session_id = Self::create_session(device, algo, Self::DECRYPT, key, tag.len() as u32, aad.len() as u32);
        let dst_data = Self::encrypt_or_decrypt(
            device,
            algo,
            session_id,
            Self::ENCRYPT,
            iv,
            aad,
            src_data,
            dst_data_len,
            tag,
        );
        Self::send_destroy_session_request(device, session_id);
        dst_data
    }
}
