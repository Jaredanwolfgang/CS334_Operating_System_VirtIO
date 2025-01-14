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
                aead::SupportedAeads, akcipher::*, hash::*, mac::SupportedMacs, services::{CryptoServiceMap, SupportedCryptoServices}, sym::*
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
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        ];
        let data2: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D
        ];
        
        early_println!("[Test] Original data for CIPHER: {:?}", data1);
        let cipher_encrypt_result = Cipher::encrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &data1);
        early_println!("[Test] Encrypted data for CIPHER: {:?}", cipher_encrypt_result);
        let cipher_decrypt_result = Cipher::decrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &cipher_encrypt_result);
        early_println!("[Test] Decrypted data for CIPHER: {:?}", cipher_decrypt_result);

        assert_eq!(data1, cipher_decrypt_result, "[Test] The initial data and decrypted data of CIPHER are inconsistent");
        early_println!("[Test] CIPHER test pass!");

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
        let pub_key: Vec<u8> = vec![48, 130, 1, 10, 2, 130, 1, 1, 0, 208, 151, 92, 100, 11, 76, 13, 76, 92, 37, 235, 53, 116, 1, 50, 88, 192, 252, 33, 74, 156, 205, 173, 243, 7, 209, 221, 175, 188, 217, 169, 109, 249, 144, 105, 91, 248, 115, 210, 157, 180, 72, 182, 79, 4, 205, 255, 50, 159, 155, 173, 187, 10, 172, 207, 207, 86, 166, 38, 248, 242, 35, 105, 73, 5, 62, 147, 33, 68, 223, 8, 166, 252, 177, 21, 233, 57, 106, 56, 1, 208, 103, 38, 126, 44, 128, 184, 74, 208, 202, 238, 31, 132, 98, 19, 239, 137, 93, 178, 254, 245, 118, 1, 221, 48, 147, 226, 75, 204, 190, 227, 160, 116, 169, 159, 203, 253, 190, 208, 91, 149, 212, 32, 84, 42, 244, 153, 172, 1, 136, 35, 160, 24, 206, 110, 251, 193, 117, 39, 173, 98, 97, 82, 35, 103, 149, 21, 138, 193, 253, 237, 54, 94, 66, 183, 140, 120, 237, 98, 198, 247, 152, 239, 131, 122, 165, 242, 200, 111, 47, 79, 7, 117, 133, 112, 127, 124, 124, 46, 198, 195, 115, 61, 243, 139, 183, 101, 106, 56, 25, 124, 212, 248, 188, 48, 174, 233, 32, 252, 15, 194, 241, 220, 175, 212, 203, 198, 64, 150, 131, 243, 6, 18, 134, 195, 246, 217, 42, 101, 154, 48, 189, 54, 176, 243, 232, 178, 228, 246, 209, 219, 54, 52, 103, 102, 59, 144, 59, 55, 122, 89, 62, 114, 3, 91, 122, 139, 213, 59, 174, 41, 248, 196, 121, 43, 155, 2, 3, 1, 0, 1];
        let private_key: Vec<u8> = vec![48, 130, 4, 163, 2, 1, 0, 2, 130, 1, 1, 0, 208, 151, 92, 100, 11, 76, 13, 76, 92, 37, 235, 53, 116, 1, 50, 88, 192, 252, 33, 74, 156, 205, 173, 243, 7, 209, 221, 175, 188, 217, 169, 109, 249, 144, 105, 91, 248, 115, 210, 157, 180, 72, 182, 79, 4, 205, 255, 50, 159, 155, 173, 187, 10, 172, 207, 207, 86, 166, 38, 248, 242, 35, 105, 73, 5, 62, 147, 33, 68, 223, 8, 166, 252, 177, 21, 233, 57, 106, 56, 1, 208, 103, 38, 126, 44, 128, 184, 74, 208, 202, 238, 31, 132, 98, 19, 239, 137, 93, 178, 254, 245, 118, 1, 221, 48, 147, 226, 75, 204, 190, 227, 160, 116, 169, 159, 203, 253, 190, 208, 91, 149, 212, 32, 84, 42, 244, 153, 172, 1, 136, 35, 160, 24, 206, 110, 251, 193, 117, 39, 173, 98, 97, 82, 35, 103, 149, 21, 138, 193, 253, 237, 54, 94, 66, 183, 140, 120, 237, 98, 198, 247, 152, 239, 131, 122, 165, 242, 200, 111, 47, 79, 7, 117, 133, 112, 127, 124, 124, 46, 198, 195, 115, 61, 243, 139, 183, 101, 106, 56, 25, 124, 212, 248, 188, 48, 174, 233, 32, 252, 15, 194, 241, 220, 175, 212, 203, 198, 64, 150, 131, 243, 6, 18, 134, 195, 246, 217, 42, 101, 154, 48, 189, 54, 176, 243, 232, 178, 228, 246, 209, 219, 54, 52, 103, 102, 59, 144, 59, 55, 122, 89, 62, 114, 3, 91, 122, 139, 213, 59, 174, 41, 248, 196, 121, 43, 155, 2, 3, 1, 0, 1, 2, 130, 1, 0, 64, 203, 163, 241, 151, 232, 202, 0, 188, 103, 51, 7, 105, 191, 173, 106, 16, 152, 193, 166, 177, 202, 218, 140, 50, 19, 169, 47, 156, 20, 105, 35, 54, 112, 251, 169, 140, 38, 62, 120, 170, 182, 35, 155, 172, 60, 105, 87, 202, 104, 203, 176, 220, 130, 14, 19, 180, 48, 236, 206, 76, 57, 95, 205, 69, 9, 201, 30, 126, 140, 97, 221, 173, 133, 60, 239, 51, 220, 161, 5, 63, 61, 171, 161, 106, 37, 154, 25, 243, 125, 246, 54, 104, 35, 39, 90, 51, 107, 157, 220, 193, 87, 37, 1, 22, 195, 249, 121, 222, 98, 53, 199, 116, 53, 244, 227, 163, 49, 16, 252, 66, 48, 160, 210, 68, 125, 178, 246, 65, 201, 111, 45, 95, 253, 76, 227, 152, 105, 156, 72, 186, 15, 176, 4, 175, 123, 151, 240, 250, 15, 222, 107, 6, 216, 54, 27, 252, 180, 245, 234, 168, 151, 33, 69, 213, 227, 123, 133, 138, 193, 46, 172, 12, 125, 35, 186, 15, 207, 56, 143, 36, 216, 83, 139, 93, 8, 92, 230, 189, 213, 34, 173, 29, 239, 131, 205, 124, 86, 87, 147, 197, 186, 15, 65, 46, 24, 35, 6, 184, 173, 129, 244, 172, 223, 73, 180, 254, 201, 206, 37, 184, 153, 196, 149, 172, 39, 27, 196, 22, 151, 253, 74, 221, 114, 26, 63, 109, 166, 78, 223, 35, 221, 204, 243, 4, 106, 220, 18, 148, 24, 227, 159, 96, 13, 235, 113, 2, 129, 129, 0, 219, 113, 175, 253, 21, 65, 249, 140, 203, 6, 57, 112, 121, 162, 56, 38, 107, 251, 13, 105, 70, 137, 195, 198, 118, 131, 233, 178, 222, 100, 175, 206, 114, 150, 128, 18, 76, 132, 87, 223, 94, 224, 220, 220, 40, 240, 131, 166, 186, 130, 117, 240, 150, 35, 1, 255, 13, 128, 179, 156, 32, 65, 122, 224, 8, 170, 20, 75, 185, 102, 78, 234, 44, 128, 171, 108, 74, 51, 16, 208, 64, 80, 125, 216, 71, 102, 223, 64, 64, 176, 110, 242, 63, 204, 93, 240, 119, 189, 135, 127, 209, 40, 91, 158, 199, 69, 62, 249, 177, 151, 91, 147, 65, 166, 190, 208, 252, 157, 123, 213, 71, 187, 69, 159, 116, 223, 0, 221, 2, 129, 129, 0, 243, 86, 217, 40, 10, 174, 198, 245, 56, 156, 203, 141, 85, 125, 53, 62, 245, 2, 72, 245, 184, 181, 68, 201, 243, 108, 167, 29, 230, 121, 121, 194, 125, 203, 79, 3, 8, 215, 184, 237, 40, 222, 98, 182, 47, 222, 240, 58, 17, 117, 58, 103, 102, 72, 207, 99, 30, 172, 69, 81, 235, 84, 132, 155, 95, 31, 216, 146, 42, 31, 122, 87, 190, 194, 105, 252, 121, 231, 215, 84, 121, 117, 74, 191, 179, 201, 56, 72, 85, 35, 234, 9, 105, 151, 69, 245, 158, 9, 30, 32, 72, 74, 220, 111, 19, 163, 96, 129, 18, 141, 120, 23, 11, 40, 32, 8, 238, 126, 229, 58, 31, 80, 83, 187, 237, 109, 26, 215, 2, 129, 128, 48, 250, 31, 192, 73, 149, 79, 0, 40, 115, 252, 47, 233, 69, 214, 104, 100, 227, 68, 108, 1, 173, 79, 191, 164, 197, 238, 75, 216, 172, 250, 60, 6, 129, 38, 150, 110, 243, 126, 181, 64, 244, 200, 246, 110, 64, 183, 241, 103, 97, 36, 183, 140, 154, 197, 160, 74, 64, 54, 86, 27, 48, 226, 30, 204, 112, 65, 85, 97, 76, 191, 66, 46, 170, 141, 23, 255, 59, 132, 126, 38, 76, 144, 185, 203, 189, 223, 7, 245, 40, 43, 170, 239, 168, 74, 51, 24, 86, 121, 190, 130, 77, 18, 157, 206, 117, 219, 7, 89, 166, 161, 110, 173, 81, 108, 247, 49, 218, 104, 64, 2, 225, 126, 57, 135, 153, 26, 21, 2, 129, 129, 0, 180, 33, 252, 74, 217, 237, 155, 182, 119, 156, 10, 74, 171, 152, 46, 76, 86, 142, 196, 119, 177, 173, 238, 40, 25, 28, 187, 113, 52, 229, 131, 174, 231, 244, 18, 159, 74, 114, 118, 160, 136, 250, 102, 212, 59, 7, 171, 137, 48, 215, 56, 206, 198, 54, 235, 222, 146, 28, 48, 140, 125, 202, 105, 7, 163, 25, 45, 246, 181, 91, 235, 242, 252, 113, 106, 135, 205, 174, 68, 6, 114, 138, 211, 52, 169, 224, 48, 219, 202, 186, 245, 74, 214, 113, 119, 6, 101, 96, 150, 126, 139, 69, 111, 124, 130, 107, 20, 203, 55, 114, 166, 13, 88, 226, 241, 35, 235, 120, 224, 51, 112, 110, 196, 45, 127, 138, 158, 173, 2, 129, 128, 47, 215, 205, 53, 81, 33, 242, 45, 132, 189, 41, 113, 233, 18, 114, 209, 32, 57, 216, 65, 177, 126, 163, 98, 205, 182, 207, 164, 41, 241, 254, 164, 228, 243, 61, 199, 123, 171, 152, 80, 142, 77, 103, 144, 149, 244, 29, 6, 31, 93, 225, 244, 226, 218, 202, 169, 200, 42, 201, 12, 241, 103, 144, 35, 112, 88, 200, 135, 67, 31, 116, 231, 102, 50, 20, 115, 168, 130, 224, 182, 55, 184, 245, 248, 132, 223, 127, 219, 185, 158, 169, 3, 164, 122, 126, 207, 46, 20, 179, 9, 40, 126, 143, 208, 218, 82, 76, 139, 151, 222, 105, 205, 197, 180, 252, 26, 196, 231, 25, 111, 96, 65, 59, 76, 244, 3, 190, 39];
        // let padded_private_key = padded_private_key(&private_key).to_vec();
        
        early_println!("[Test] Original data for AKCIPHER: {:?}", data2);
        let akcipher_encrypt_result = Akcipher::akcipher(
            &device, VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_PKCS1_PADDING,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_SHA256, Akcipher::PUBLIC,
            &pub_key, VIRTIO_CRYPTO_AKCIPHER_RSA, Akcipher::ENCRYPT, &data2
        );
        early_println!("[Test] Encrypted data for AKCIPHER: {:?}", akcipher_encrypt_result);

        let akcipher_decrypt_result = Akcipher::akcipher(
            &device, VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_PKCS1_PADDING,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_SHA256, Akcipher::PRIVATE,
            &private_key, VIRTIO_CRYPTO_AKCIPHER_RSA, Akcipher::DECRYPT, &akcipher_encrypt_result
        );
        early_println!("[Test] Decrypted data for AKCIPHER: {:?}", akcipher_decrypt_result);

        assert_eq!(data2, akcipher_decrypt_result, "[Test] The initial data and decrypted data of AKCIPHER are inconsistent");
        early_println!("[Test] AKCIPHER encrypt-decrypt test pass!");
        
        early_println!("[Test] Original data for AKCIPHER: {:?}", data2);
        let akcipher_sign_result = Akcipher::akcipher(
            &device, VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_PKCS1_PADDING,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_SHA256, Akcipher::PRIVATE,
            &private_key, VIRTIO_CRYPTO_AKCIPHER_RSA, Akcipher::SIGN, &data2
        );
        early_println!("[Test] Signature for AKCIPHER: {:?}", akcipher_sign_result);

        let akcipher_verify_result = Akcipher::akcipher(
            &device, VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_PKCS1_PADDING,
            VirtioCryptoRsaSessionPara::VIRTIO_CRYPTO_RSA_SHA256, Akcipher::PUBLIC,
            &pub_key, VIRTIO_CRYPTO_AKCIPHER_RSA, Akcipher::VERIFY, &akcipher_sign_result
        );
        early_println!("[Test] Verification for AKCIPHER: {:?}", akcipher_verify_result);

        assert_eq!(data2, akcipher_verify_result, "[Test] The initial data and verification data of AKCIPHER are inconsistent");
        early_println!("[Test] AKCIPHER sign-verify test pass!");

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

fn padded_private_key(private_key: &[u8]) -> [u8; 2048] {
    let mut padded_private_key = [0u8; 2048];
    let len = private_key.len().min(2048);
    padded_private_key[..len].copy_from_slice(&private_key[..len]);
    padded_private_key
}