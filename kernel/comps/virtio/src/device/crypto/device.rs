use alloc::{sync::Arc, vec::Vec};
use core::mem::size_of;

use log::debug;
use ostd::{
    early_println,
    mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions},
    sync::SpinLock,
};

use super::config::{CryptoFeatures, VirtioCryptoConfig};
use crate::{
    device::{
        crypto::{
            header::{
                VirtioCryptoCreateSessionInput, VirtioCryptoCtrlHeader,
                VIRTIO_CRYPTO_HASH_CREATE_SESSION,
            },
            service::{
                aead::SupportedAeads,
                akcipher::SupportedAkCiphers,
                cipher::SupportedCiphers,
                hash::{SupportedHashes, VIRTIO_CRYPTO_HASH_SHA1},
                mac::SupportedMacs,
                services::{CryptoServiceMap, SupportedCryptoServices},
            },
        },
        VirtioDeviceError,
    },
    queue::VirtQueue,
    transport::ConfigManager,
    Box, VirtioTransport,
};

pub struct CryptoDevice {
    pub config_manager: ConfigManager<VirtioCryptoConfig>,
    pub request_buffer: DmaStream,
    pub response_buffer: DmaStream,
    pub dataqs: Vec<SpinLock<VirtQueue>>,
    pub controlq: SpinLock<VirtQueue>,
    pub transport: SpinLock<Box<dyn VirtioTransport>>,
    pub supported_crypto_services: CryptoServiceMap,
}

impl CryptoDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        // TODO: 根据设备要求进行功能选择

        early_println!("negotiating features: {:#x}", features);

        let mut support_features = CryptoFeatures::from_bits_truncate(features);

        if (support_features & CryptoFeatures::VIRTIO_CRYPTO_F_REVISION_1).bits() == 0 {
            support_features.remove(CryptoFeatures::VIRTIO_CRYPTO_F_CIPHER_STATELESS_MODE);
            support_features.remove(CryptoFeatures::VIRTIO_CRYPTO_F_HASH_STATELESS_MODE);
            support_features.remove(CryptoFeatures::VIRTIO_CRYPTO_F_MAC_STATELESS_MODE);
            support_features.remove(CryptoFeatures::VIRTIO_CRYPTO_F_AEAD_STATELESS_MODE);
            support_features.remove(CryptoFeatures::VIRTIO_CRYPTO_F_AKCIPHER_STATELESS_MODE);
        }

        support_features.bits() as u64
    }

    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {
        let config_manager = VirtioCryptoConfig::new_manager(transport.as_ref());
        let config = config_manager.read_config();
        early_println!("virtio_crypto_config = {:#?}", config);

        // 初始化设备，下面的代码需要修改
        // 创建数据队列 (dataq)
        let mut dataqs = Vec::with_capacity(config.max_dataqueues as usize);

        // TODO: DATAQ_SIZE未知，暂且设置为2
        const DATAQ_SIZE: u16 = 2;

        // 根据白皮书2.6节的定义，max_dataqueues的数据内容不应超过u16
        let max_dataqueues = config.max_dataqueues;
        if max_dataqueues > u16::MAX as u32 {
            // max_dataqueues的数据范围不符合规范
            // TODO: 可能需要重启设备
            panic!("config.max_dataqueues out of bound.");
        }

        for dataq_index in 0..max_dataqueues {
            // config.max_dataqueues为u32类型，但VirtQueue::new()中接收的idx数据为u16
            // 因此这里需要强行将u32转换成u16，此前代码已经保证max_dataqueues的数据范围不超过u16

            let dataq_index: u16 = dataq_index as u16;
            let dataq =
                SpinLock::new(VirtQueue::new(dataq_index, DATAQ_SIZE, transport.as_mut()).unwrap());
            dataqs.push(dataq);
        }

        // TODO: CONTROLQ_SIZE未知，暂且设置为2
        const CONTROLQ_SIZE: u16 = 2;
        // 同上，强行转换为u16
        let controlq_index: u16 = max_dataqueues as u16;
        let controlq = SpinLock::new(
            VirtQueue::new(controlq_index, CONTROLQ_SIZE, transport.as_mut()).unwrap(),
        );

        let request_buffer = {
            let vm_segment = FrameAllocOptions::new(1).alloc_contiguous().unwrap();
            DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap()
        };

        let response_buffer = {
            let vm_segment = FrameAllocOptions::new(1).alloc_contiguous().unwrap();
            DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap()
        };

        // 创建设备实例
        let device = Arc::new(Self {
            config_manager,
            request_buffer,
            response_buffer,
            dataqs,
            controlq,
            transport: SpinLock::new(transport),
            supported_crypto_services: CryptoServiceMap::new(config),
        });

        // 完成设备初始化
        device.transport.lock().finish_init();

        // 测试设备
        test_device(device);

        Ok(())
    }

    fn print_supported_crypto_algorithms(&self) {
        early_println!("Supported Crypto Services and Algorithms:");

        let supported_ciphers_name = self
            .supported_crypto_services
            .supported_ciphers
            .get_supported_ciphers_name();
        if supported_ciphers_name.len() > 0 {
            early_println!("- CIPHER");
        }
        for cipher_name in supported_ciphers_name {
            early_println!("  - {}", cipher_name);
        }

        let supported_hashes_name = self
            .supported_crypto_services
            .supported_hashes
            .get_supported_hashes_name();
        if supported_hashes_name.len() > 0 {
            early_println!("- HASH");
        }
        for hash_name in supported_hashes_name {
            early_println!("  - {}", hash_name);
        }

        let supported_macs_name = self
            .supported_crypto_services
            .supported_macs
            .get_supported_macs_name();
        if supported_macs_name.len() > 0 {
            early_println!("- MAC");
        }
        for mac_name in supported_macs_name {
            early_println!("  - {}", mac_name);
        }

        let supported_aeads_name = self
            .supported_crypto_services
            .supported_aeads
            .get_supported_aeads_name();
        if supported_aeads_name.len() > 0 {
            early_println!("- AEAD");
        }
        for aead_name in supported_aeads_name {
            early_println!("  - {}", aead_name);
        }

        let supported_akciphers_name = self
            .supported_crypto_services
            .supported_akciphers
            .get_supported_akciphers_name();
        if supported_akciphers_name.len() > 0 {
            early_println!("- AKCIPHER");
        }
        for akcipher_name in supported_akciphers_name {
            early_println!("  - {}", akcipher_name);
        }
    }
}

fn test_device(device: Arc<CryptoDevice>) {
    device.print_supported_crypto_algorithms();
    let req_buffer = &device.request_buffer;

    // 测试HASH

    const REQ_SIZE: usize = size_of::<VirtioCryptoCtrlHeader>();

    let id = 0;
    let req_slice = {
        let req_slice = DmaStreamSlice::new(req_buffer, id * REQ_SIZE, REQ_SIZE);
        let header = VirtioCryptoCtrlHeader {
            opcode: VIRTIO_CRYPTO_HASH_CREATE_SESSION,
            algo: VIRTIO_CRYPTO_HASH_SHA1,
            // stateless mode may use flag
            flag: 0,
            reserved: 0,
        };
        req_slice
            .write_val(0, &header).unwarp();
        req_slice.sync().unwrap();
        req_slice
    };

    const RESP_SIZE: usize = size_of::<VirtioCryptoCreateSessionInput>();

    let resp_slice = {
        let resp_slice = DmaStreamSlice::new(&device.response_buffer, id * RESP_SIZE, RESP_SIZE);
        resp_slice
            .write_val(0, &VirtioCryptoCreateSessionInput::default())
            .unwrap();
        resp_slice
    };

    let queue = device.controlq.disable_irq().lock();

    let token = queue
        .add_dma_buf(&[&req_slice], &[&resp_slice])
        .expect("add queue failed");
    if queue.should_notify() {
        queue.notify();
    }

    resp_slice.sync().unwrap();
    let resp: VirtioCryptoCreateSessionInput = resp_slice.read_val(0).unwarp();
    early_println!("Status: {}", resp);

    // // let mut request_queue = device.controlq.lock();
    // let request_buffer = device.request_buffer.clone();
    // let value = request_buffer.reader().unwrap().read_once::<u64>().unwrap();
    // let mut writer = request_buffer.writer().unwrap();

    // let mut len: usize = 0;
    // writer.write_val(&header).unwrap();
    // len += core::mem::size_of::<VirtioCryptoCtrlHeader>();

    // request_buffer.sync(0..len).unwrap();
    // let value = request_buffer.reader().unwrap().read_once::<u64>().unwrap();
    // early_println!("After value:{:x}", value);
}
