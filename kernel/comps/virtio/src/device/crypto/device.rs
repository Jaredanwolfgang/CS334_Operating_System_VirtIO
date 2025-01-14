use core::usize;

use alloc::{sync::Arc, vec::Vec};
use id_alloc::IdAlloc;
use alloc::vec;
use ostd::{
    early_println, mm::{DmaDirection, DmaStream, FrameAllocOptions}, sync::SpinLock, Pod
};
use super::config::{CryptoFeatures, VirtioCryptoConfig};
use crate::{
    device::{
        crypto::service::{
                akcipher::{Akcipher, VirtioCryptoRsaSessionPara, VIRTIO_CRYPTO_AKCIPHER_RSA}, services::CryptoServiceMap, sym::*
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
    pub request_buffer_allocator: SpinLock<SliceAllocator>,
    pub response_buffer_allocator: SpinLock<SliceAllocator>,
    pub dataqs: Vec<SpinLock<VirtQueue>>,
    pub controlq: SpinLock<VirtQueue>,
    pub transport: SpinLock<Box<dyn VirtioTransport>>,
    pub supported_crypto_services: CryptoServiceMap,
}

impl CryptoDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        // early_println!("negotiating features: {:#x}", features);
        let mut support_features = CryptoFeatures::from_bits_truncate(features);

        // 实现REVISION_1后将该行删去即可
        support_features.remove(CryptoFeatures::VIRTIO_CRYPTO_F_REVISION_1);

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

        // DATAQ_SIZE设置为128
        const DATAQ_SIZE: u16 = 128;

        // 根据白皮书2.6节的定义，max_dataqueues的数据内容不应超过u16
        let max_dataqueues = config.max_dataqueues;
        if max_dataqueues > u16::MAX as u32 {
            // max_dataqueues的数据范围不符合规范
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

        // CONTROLQ_SIZE设置为128
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

        let request_buffer_size = request_buffer.nbytes();
        let response_buffer_size = response_buffer.nbytes();

        let request_buffer_allocator = SliceAllocator::new(request_buffer_size, 8);
        let response_buffer_allocator = SliceAllocator::new(response_buffer_size, 8);

        // 创建设备实例
        let device = Arc::new(Self {
            config_manager,
            request_buffer,
            response_buffer,
            request_buffer_allocator: SpinLock::new(request_buffer_allocator),
            response_buffer_allocator: SpinLock::new(response_buffer_allocator),
            dataqs,
            controlq,
            transport: SpinLock::new(transport),
            supported_crypto_services: CryptoServiceMap::new(config),
        });

        // 完成设备初始化
        device.transport.lock().finish_init();

        device.print_supported_crypto_algorithms();
        Self::test_device(device)
    }

    pub fn test_device(device: Arc<CryptoDevice>) -> Result<(), VirtioDeviceError> {
        let cipher_key = [0 as u8; 16];
        let iv = vec![0x00; 16];
        // let src_data = vec![
        //     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        //     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        // ];
        let data1: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        let data2: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D
        ];
        
        let encrypted_data = Cipher::encrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &data1);
        let decrypted_data = Cipher::decrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &encrypted_data);

        assert_eq!(data1, decrypted_data, "The initial data and decrypted data of CIPHER are inconsistent");

        // Testing chain algorithm: qemu-backend doesn't support
        // let mut chain_alg = ChainAlg::new(
        //     ChainAlg::ENCRYPT,
        //     VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
        //     VIRTIO_CRYPTO_SYM_HASH_MODE_PLAIN,
        //     VIRTIO_CRYPTO_HASH_SHA1,
        //     VIRTIO_CRYPTO_CIPHER_AES_CBC,
        // );
        // let chain_alg_result = chain_alg.chaining_algorithms(&device, &cipher_key, &[], &iv, &data);
        // early_println!("Result for chaining algorithm: ");
        // early_println!("{:?}", chain_alg_result);

        // akcipher_key需要修改以满足rsa算法的要求
        // 否则直接调用该方法会使device返回Err
        // [Fail] let akcipher_key = vec![48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 196, 188, 24, 75, 124, 246, 117, 46, 227, 245, 55, 148, 204, 252, 111, 70, 114, 212, 251, 97, 70, 231, 127, 4, 67, 250, 202, 131, 161, 108, 17, 59, 193, 26, 188, 172, 179, 202, 91, 120, 82, 177, 105, 199, 251, 246, 7, 200, 169, 132, 223, 94, 111, 49, 214, 142, 98, 30, 58, 44, 139, 100, 26, 68, 244, 248, 248, 53, 150, 202, 237, 167, 106, 38, 242, 54, 246, 91, 168, 118, 175, 72, 208, 0, 201, 135, 157, 53, 221, 97, 37, 216, 71, 246, 66, 24, 68, 75, 7, 150, 201, 114, 220, 94, 131, 17, 213, 236, 200, 239, 90, 4, 128, 95, 184, 40, 127, 78, 47, 16, 124, 225, 225, 160, 120, 92, 141, 33, 118, 175, 84, 104, 206, 230, 160, 188, 29, 201, 26, 76, 136, 34, 51, 49, 245, 82, 194, 237, 204, 202, 173, 38, 129, 30, 203, 214, 222, 75, 183, 212, 184, 204, 63, 83, 27, 225, 187, 94, 114, 226, 243, 196, 238, 138, 87, 66, 154, 109, 33, 243, 184, 192, 214, 148, 164, 124, 53, 194, 165, 91, 116, 105, 84, 80, 198, 208, 89, 231, 143, 86, 36, 163, 112, 6, 76, 38, 18, 58, 171, 245, 36, 129, 14, 30, 203, 157, 8, 104, 81, 189, 209, 126, 80, 3, 128, 183, 250, 106, 249, 190, 207, 53, 159, 89, 41, 171, 81, 92, 88, 148, 224, 227, 76, 235, 177, 19, 3, 116, 233, 59, 102, 174, 177, 204, 192, 147, 71, 127, 230, 81, 234, 100, 206, 255, 240, 67, 104, 12, 85, 116, 7, 9, 201, 251, 225, 158, 143, 231, 196, 82, 93, 173, 236, 38, 225, 183, 81, 45, 145, 75, 89, 21, 186, 134, 187, 179, 165, 31, 65, 162, 16, 208, 228, 186, 124, 63, 202, 68, 170, 140, 146, 170, 242, 197, 40, 39, 210, 205, 54, 146, 181, 29, 219, 6, 81, 158, 244, 183, 84, 234, 2, 132, 11, 22, 10, 104, 220, 197, 228, 234, 180, 242, 139, 149, 35, 18, 49, 58, 204, 11, 201, 130, 238, 157, 20, 203, 139, 190, 189, 234, 180, 219, 133, 228, 244, 65, 199, 167, 224, 84, 155, 8, 143, 139, 38, 197, 203, 18, 186, 23, 226, 196, 139, 219, 78, 101, 246, 19, 155, 146, 197, 212, 66, 81, 132, 146, 31, 5, 244, 133, 250, 182, 148, 204, 178, 51, 91, 52, 3, 8, 48, 108, 107, 33, 7, 23, 65, 44, 81, 72, 160, 95, 218, 100, 18, 10, 210, 179, 75, 75, 89, 34, 74, 120, 94, 159, 110, 42, 128, 33, 116, 145, 118, 103, 161, 132, 232, 161, 18, 157, 136, 227, 88, 129, 86, 171, 56, 159, 169, 235, 200, 57, 54, 252, 193, 48, 107, 146, 228, 44, 209, 198, 174, 100, 107, 159, 139, 66, 1, 0, 138, 23, 252, 106, 111, 120, 198, 31, 35, 157, 91, 60, 102, 7, 165, 240, 89, 29, 176, 16, 249, 207, 99, 117, 124, 81, 98, 113, 103, 187, 60, 3, 2, 3, 1, 0, 1];
        // [Fail] let akcipher_key = vec![48, 130, 2, 34, 2, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 196, 188, 24, 75, 124, 246, 117, 46, 227, 245, 55, 148, 204, 252, 111, 70, 114, 212, 251, 97, 70, 231, 127, 4, 67, 250, 202, 131, 161, 108, 17, 59, 193, 26, 188, 172, 179, 202, 91, 120, 82, 177, 105, 199, 251, 246, 7, 200, 169, 132, 223, 94, 111, 49, 214, 142, 98, 30, 58, 44, 139, 100, 26, 68, 244, 248, 248, 53, 150, 202, 237, 167, 106, 38, 242, 54, 246, 91, 168, 118, 175, 72, 208, 0, 201, 135, 157, 53, 221, 97, 37, 216, 71, 246, 66, 24, 68, 75, 7, 150, 201, 114, 220, 94, 131, 17, 213, 236, 200, 239, 90, 4, 128, 95, 184, 40, 127, 78, 47, 16, 124, 225, 225, 160, 120, 92, 141, 33, 118, 175, 84, 104, 206, 230, 160, 188, 29, 201, 26, 76, 136, 34, 51, 49, 245, 82, 194, 237, 204, 202, 173, 38, 129, 30, 203, 214, 222, 75, 183, 212, 184, 204, 63, 83, 27, 225, 187, 94, 114, 226, 243, 196, 238, 138, 87, 66, 154, 109, 33, 243, 184, 192, 214, 148, 164, 124, 53, 194, 165, 91, 116, 105, 84, 80, 198, 208, 89, 231, 143, 86, 36, 163, 112, 6, 76, 38, 18, 58, 171, 245, 36, 129, 14, 30, 203, 157, 8, 104, 81, 189, 209, 126, 80, 3, 128, 183, 250, 106, 249, 190, 207, 53, 159, 89, 41, 171, 81, 92, 88, 148, 224, 227, 76, 235, 177, 19, 3, 116, 233, 59, 102, 174, 177, 204, 192, 147, 71, 127, 230, 81, 234, 100, 206, 255, 240, 67, 104, 12, 85, 116, 7, 9, 201, 251, 225, 158, 143, 231, 196, 82, 93, 173, 236, 38, 225, 183, 81, 45, 145, 75, 89, 21, 186, 134, 187, 179, 165, 31, 65, 162, 16, 208, 228, 186, 124, 63, 202, 68, 170, 140, 146, 170, 242, 197, 40, 39, 210, 205, 54, 146, 181, 29, 219, 6, 81, 158, 244, 183, 84, 234, 2, 132, 11, 22, 10, 104, 220, 197, 228, 234, 180, 242, 139, 149, 35, 18, 49, 58, 204, 11, 201, 130, 238, 157, 20, 203, 139, 190, 189, 234, 180, 219, 133, 228, 244, 65, 199, 167, 224, 84, 155, 8, 143, 139, 38, 197, 203, 18, 186, 23, 226, 196, 139, 219, 78, 101, 246, 19, 155, 146, 197, 212, 66, 81, 132, 146, 31, 5, 244, 133, 250, 182, 148, 204, 178, 51, 91, 52, 3, 8, 48, 108, 107, 33, 7, 23, 65, 44, 81, 72, 160, 95, 218, 100, 18, 10, 210, 179, 75, 75, 89, 34, 74, 120, 94, 159, 110, 42, 128, 33, 116, 145, 118, 103, 161, 132, 232, 161, 18, 157, 136, 227, 88, 129, 86, 171, 56, 159, 169, 235, 200, 57, 54, 252, 193, 48, 107, 146, 228, 44, 209, 198, 174, 100, 107, 159, 139, 66, 1, 0, 138, 23, 252, 106, 111, 120, 198, 31, 35, 157, 91, 60, 102, 7, 165, 240, 89, 29, 176, 16, 249, 207, 99, 117, 124, 81, 98, 113, 103, 187, 60, 3, 2, 3, 1, 0, 1];
        let akcipher_key: Vec<u8> = vec![48, 130, 2, 34, 2, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 2, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 196, 188, 24, 75, 124, 246, 117, 46, 227, 245, 55, 148, 204, 252, 111, 70, 114, 212, 251, 97, 70, 231, 127, 4, 67, 250, 202, 131, 161, 108, 17, 59, 193, 26, 188, 172, 179, 202, 91, 120, 82, 177, 105, 199, 251, 246, 7, 200, 169, 132, 223, 94, 111, 49, 214, 142, 98, 30, 58, 44, 139, 100, 26, 68, 244, 248, 248, 53, 150, 202, 237, 167, 106, 38, 242, 54, 246, 91, 168, 118, 175, 72, 208, 0, 201, 135, 157, 53, 221, 97, 37, 216, 71, 246, 66, 24, 68, 75, 7, 150, 201, 114, 220, 94, 131, 17, 213, 236, 200, 239, 90, 4, 128, 95, 184, 40, 127, 78, 47, 16, 124, 225, 225, 160, 120, 92, 141, 33, 118, 175, 84, 104, 206, 230, 160, 188, 29, 201, 26, 76, 136, 34, 51, 49, 245, 82, 194, 237, 204, 202, 173, 38, 129, 30, 203, 214, 222, 75, 183, 212, 184, 204, 63, 83, 27, 225, 187, 94, 114, 226, 243, 196, 238, 138, 87, 66, 154, 109, 33, 243, 184, 192, 214, 148, 164, 124, 53, 194, 165, 91, 116, 105, 84, 80, 198, 208, 89, 231, 143, 86, 36, 163, 112, 6, 76, 38, 18, 58, 171, 245, 36, 129, 14, 30, 203, 157, 8, 104, 81, 189, 209, 126, 80, 3, 128, 183, 250, 106, 249, 190, 207, 53, 159, 89, 41, 171, 81, 92, 88, 148, 224, 227, 76, 235, 177, 19, 3, 116, 233, 59, 102, 174, 177, 204, 192, 147, 71, 127, 230, 81, 234, 100, 206, 255, 240, 67, 104, 12, 85, 116, 7, 9, 201, 251, 225, 158, 143, 231, 196, 82, 93, 173, 236, 38, 225, 183, 81, 45, 145, 75, 89, 21, 186, 134, 187, 179, 165, 31, 65, 162, 16, 208, 228, 186, 124, 63, 202, 68, 170, 140, 146, 170, 242, 197, 40, 39, 210, 205, 54, 146, 181, 29, 219, 6, 81, 158, 244, 183, 84, 234, 2, 132, 11, 22, 10, 104, 220, 197, 228, 234, 180, 242, 139, 149, 35, 18, 49, 58, 204, 11, 201, 130, 238, 157, 20, 203, 139, 190, 189, 234, 180, 219, 133, 228, 244, 65, 199, 167, 224, 84, 155, 8, 143, 139, 38, 197, 203, 18, 186, 23, 226, 196, 139, 219, 78, 101, 246, 19, 155, 146, 197, 212, 66, 81, 132, 146, 31, 5, 244, 133, 250, 182, 148, 204, 178, 51, 91, 52, 3, 8, 48, 108, 107, 33, 7, 23, 65, 44, 81, 72, 160, 95, 218, 100, 18, 10, 210, 179, 75, 75, 89, 34, 74, 120, 94, 159, 110, 42, 128, 33, 116, 145, 118, 103, 161, 132, 232, 161, 18, 157, 136, 227, 88, 129, 86, 171, 56, 159, 169, 235, 200, 57, 54, 252, 193, 48, 107, 146, 228, 44, 209, 198, 174, 100, 107, 159, 139, 66, 1, 0, 138, 23, 252, 106, 111, 120, 198, 31, 35, 157, 91, 60, 102, 7, 165, 240, 89, 29, 176, 16, 249, 207, 99, 117, 124, 81, 98, 113, 103, 187, 60, 3, 2, 3, 1, 0, 1];
        let akcipher_result = Akcipher::akcipher(
            &device, VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_RAW_PADDING,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_NO_HASH, Akcipher::PUBLIC,
            &akcipher_key, VIRTIO_CRYPTO_AKCIPHER_RSA, Akcipher::ENCRYPT, &data2
        );
        early_println!("{:?}", akcipher_result);


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

pub struct SliceAllocator {
    stream_size: usize,
    id_allocator: SpinLock<IdAlloc>,
    space_slices: Vec<SpaceSlice>,
}

impl SliceAllocator {
    pub fn new(stream_size: usize, id_capacity: usize) -> Self {
        SliceAllocator {
            stream_size,
            id_allocator: SpinLock::new(IdAlloc::with_capacity(id_capacity)),
            space_slices: {
                let mut space_slices = Vec::new();
                space_slices.push(SpaceSlice { head: 0, tail: stream_size,});
                space_slices
            },
        }
    }

    pub fn allocate(&mut self, size: usize) -> Result<SliceRecord, &'static str> {
        let len = self.space_slices.len();
        let mut slice_record = SliceRecord {
            id: 0,
            head: 0,
            tail: 0,
        };
        let mut allocated = false;
        for i in 0..len {
            let head = self.space_slices[i].head;
            let tail = self.space_slices[i].tail;
            if tail - head >= size {
                slice_record.head = head;
                slice_record.tail = head + size;
                let _ = &mut self.space_slices.remove(i);
                if slice_record.tail != tail {
                    self.space_slices.insert(i, SpaceSlice::new(slice_record.tail, tail));
                }
                allocated = true;
                slice_record.id = self.id_allocator.disable_irq().lock().alloc().unwrap();
                break;
            }
        }

        match allocated {
            true => Ok(slice_record),
            false => Err("no enough space"),
        }
    }

    fn deallocate(&mut self, slice_record: &SliceRecord) {
        let len: i32 = self.space_slices.len() as i32;
        for j in 0..(len + 1) {
            let i = j - 1;

            let prev_tail = match i {
                -1 => 0,
                _ => self.space_slices[i as usize].tail,
            };

            let next_head = {
                if i == len {
                    usize::MAX
                } else {
                    self.space_slices[(i+1) as usize].head
                }
            };

            if slice_record.head >= prev_tail && slice_record.head <= next_head {
                if slice_record.head == prev_tail && slice_record.tail == next_head && i != -1 && j != len {
                    self.space_slices[i as usize].tail = self.space_slices[j as usize].tail;
                    self.space_slices.remove(j as usize);
                } else if slice_record.head == prev_tail && i != -1 {
                    self.space_slices[i as usize].tail = slice_record.tail;
                } else if slice_record.tail == next_head && j != len {
                    self.space_slices[j as usize].head = slice_record.head;
                } else {
                    self.space_slices.insert(j as usize, SpaceSlice::new(slice_record.head, slice_record.tail));
                }

                break;
            }
            
        }
    }

    pub fn print(&self) {
        early_println!("--------");
        for space_slice in &self.space_slices {
            early_println!("{:?}", space_slice);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct SliceRecord {
    id: usize,
    head: usize,
    tail: usize,
}

impl SliceRecord {
    pub fn default() -> Self {
        Self {
            id: 0,
            head: 0,
            tail: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct SpaceSlice {
    head: usize,
    tail: usize,
}

impl SpaceSlice {
    fn new(head: usize, tail: usize) -> Self {
        Self {
            head,
            tail,
        }
    }
}