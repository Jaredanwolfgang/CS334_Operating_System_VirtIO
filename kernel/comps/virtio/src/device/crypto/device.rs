// use log::debug;
// use ostd::mm::{DmaStream, FrameAllocOptions, DmaDirection};
use ostd::sync::SpinLock;
use ostd::early_println;
use alloc::sync::Arc;
use alloc::vec::Vec;
use super::config::{
    VirtioCryptoConfig,
    CryptoFeatures,
};

use crate::queue::VirtQueue;
use crate::Box;
use crate::VirtioTransport;
use crate::device::VirtioDeviceError;
use crate::transport::ConfigManager;
use crate::device::crypto::service::{
    services::SupportedCryptoServices,
    cipher::SupportedCiphers,
    hash::SupportedHashes,
    mac::SupportedMacs,
    aead::SupportedAeads,
    akcipher::SupportedAkCiphers,
};
use crate::device::crypto::header::VirtioCryptoCtrlHeader;

pub struct CryptoDevice {
    pub config_manager: ConfigManager<VirtioCryptoConfig>,
    pub dataqs: Vec<SpinLock<VirtQueue>>,
    pub controlq: SpinLock<VirtQueue>,
    pub transport: SpinLock<Box<dyn VirtioTransport>>,
}

impl CryptoDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        // TODO: 根据设备要求进行功能选择

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
            let dataq = SpinLock::new(VirtQueue::new(dataq_index, DATAQ_SIZE, transport.as_mut()).unwrap());
            dataqs.push(dataq);
        }

        // TODO: CONTROLQ_SIZE未知，暂且设置为1
        const CONTROLQ_SIZE: u16 = 2;
        // 同上，强行转换为u16
        let controlq_index: u16 = max_dataqueues as u16;
        let controlq = SpinLock::new(VirtQueue::new(controlq_index, CONTROLQ_SIZE, transport.as_mut()).unwrap());

        // 创建设备实例
        let device = Arc::new(
            Self {
                config_manager,
                dataqs,
                controlq,
                transport: SpinLock::new(transport),
            }
        );
        
        // 完成设备初始化
        device.transport.lock().finish_init();

        // 测试设备
        test_device(device);

        Ok(())
    }
}

fn test_device(device: Arc<CryptoDevice>) {
    let config = device.config_manager.read_config();

    // Crypto Services
    let crypto_services_config = config.crypto_services;
    let supported_crypto_services = SupportedCryptoServices::from_u32(crypto_services_config);
    let supported_crypto_services_name = supported_crypto_services.get_supported_crypto_services_name();

    early_println!("Supported Crypto Services:");
    for crypto_service_name in supported_crypto_services_name {
        early_println!("{}", crypto_service_name);
    }

    if supported_crypto_services.contains(SupportedCryptoServices::CIPHER) {
        // Cipher
        // 合并成一个64位值
        let cipher_config = ((config.cipher_algo_h as u64) << 32) | config.cipher_algo_l as u64;
        let supported_ciphers = SupportedCiphers::from_u64(cipher_config);
        let supported_ciphers_name = supported_ciphers.get_supported_ciphers_name();

        early_println!("Supported CIPHER Algorithms:");
        for cipher_name in supported_ciphers_name {
            early_println!("{}", cipher_name);
        }
    }

    if supported_crypto_services.contains(SupportedCryptoServices::HASH) {
        // Hash
        let hash_config = config.hash_algo;
        let supported_hashes = SupportedHashes::from_u32(hash_config);
        let supported_hashes_name = supported_hashes.get_supported_hashes_name();

        early_println!("Supported HASH Algorithms:");
        for hash_name in supported_hashes_name {
            early_println!("{}", hash_name);
        }
    }

    if supported_crypto_services.contains(SupportedCryptoServices::MAC) {
        // Mac
        // 合并成一个64位值
        let mac_config = ((config.mac_algo_h as u64) << 32) | config.mac_algo_l as u64;
        let supported_macs = SupportedMacs::from_u64(mac_config);
        let supported_macs_name = supported_macs.get_supported_macs_name();

        early_println!("Supported MAC Algorithms:");
        for mac_name in supported_macs_name {
            early_println!("{}", mac_name);
        }
    }

    if supported_crypto_services.contains(SupportedCryptoServices::AEAD) {
        // AEAD
        let aead_config = config.aead_algo;
        let supported_aeads = SupportedAeads::from_u32(aead_config);
        let supported_aeads_name = supported_aeads.get_supported_aeads_name();

        early_println!("Supported AEAD Algorithms:");
        for aead_name in supported_aeads_name {
            early_println!("{}", aead_name);
        }
    }

    if supported_crypto_services.contains(SupportedCryptoServices::AKCIPHER) {
        // AKCIPHER
        let akcipher_config = config.akcipher_algo;
        let supported_akciphers = SupportedAkCiphers::from_u32(akcipher_config);
        let supported_akciphers_name = supported_akciphers.get_supported_akciphers_name();

        early_println!("Supported AKCIPHER Algorithms:");
        for akcipher_name in supported_akciphers_name {
            early_println!("{}", akcipher_name);
        }
    }

    // // 测试转换
    // let header = VirtioCryptoCtrlHeader {
    //     opcode: 1,
    //     algo: 2,
    //     flag: 3,
    //     reserved: 0,
    // };

    // let byte_array = header.to_byte_array();

    // // 打印字节数组
    // early_println!("{:?}", byte_array);

}

