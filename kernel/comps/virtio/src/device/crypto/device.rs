use alloc::{sync::Arc, vec::Vec};
use aster_bigtcp::device;
use typeflags_util::assert;
use core::{hint::spin_loop, mem::size_of};
use log::debug;
use id_alloc::IdAlloc;
use alloc::vec;
use ostd::{
    early_println,
    mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions},
    sync::SpinLock,
    Pod,
    mm::VmIo
};
use super::{config::{CryptoFeatures, VirtioCryptoConfig}, service::services::VIRTIO_CRYPTO_SERVICE_CIPHER};
use crate::{
    device::{
        crypto::{
            header::*,
            service::{
                aead::SupportedAeads, akcipher::{Akcipher, SupportedAkCiphers, VirtioCryptoRsaSessionPara}, hash::*, mac::SupportedMacs, services::{CryptoServiceMap, SupportedCryptoServices}, sym::*
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
    pub id_allocator: SpinLock<IdAlloc>,
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
        const DATAQ_SIZE: u16 = 64;

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
        const CONTROLQ_SIZE: u16 = 128;
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
            id_allocator: SpinLock::new(IdAlloc::with_capacity(64)),
            supported_crypto_services: CryptoServiceMap::new(config),
        });

        // 完成设备初始化
        device.transport.lock().finish_init();

        Self::test_device(device)
    }

    pub fn test_device(device: Arc<CryptoDevice>) -> Result<(), VirtioDeviceError> {
        let cipher_key = [0 as u8; 16];
        let iv = vec![0x00; 16];
        // let src_data = vec![
        //     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        //     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        // ];
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        
        // let encrypted_data = Cipher::encrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &data);
        // let decrypted_data = Cipher::decrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &encrypted_data);

        // assert_eq!(data, decrypted_data, "The initial data and decrypted data of CIPHER are inconsistent");

        let mut chain_alg = ChainAlg::new(
            ChainAlg::ENCRYPT,
            VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
            VIRTIO_CRYPTO_SYM_HASH_MODE_PLAIN,
            VIRTIO_CRYPTO_HASH_SHA1,
            VIRTIO_CRYPTO_CIPHER_AES_CBC,
        );
        let encrypt_then_hash_result = chain_alg.encrypt_then_hash(&device, &cipher_key, &[], &iv, &data);
        early_println!("Result for encrypt then hash: ");
        early_println!("{:?}", encrypt_then_hash_result);

        // akcipher_key需要修改以满足rsa算法的要求
        // 否则直接调用该方法会使device返回Err
        // let akcipher_key = [0 as u8; 16];
        // Akcipher::create_session_rsa(&device, VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_RAW_PADDING, VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_NO_HASH, Akcipher::PUBLIC, &akcipher_key);

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

fn slice_to_padded_array(slice: &[u8]) -> [u8; 56] {
    let mut array = [0u8; 56]; // Initialize with zeroes
    let len = slice.len().min(56); // Ensure we don't exceed 56
    array[..len].copy_from_slice(&slice[..len]); // Copy the slice into the array
    array
}