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
                services::CryptoServiceMap, sym::*
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
        
        let encrypted_data = Cipher::encrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &data);
        let decrypted_data = Cipher::decrypt(&device, VIRTIO_CRYPTO_CIPHER_AES_CBC, &cipher_key, &iv, &encrypted_data);

        assert_eq!(data, decrypted_data, "The initial data and decrypted data of CIPHER are inconsistent");

        // let mut chain_alg = ChainAlg::new(
        //     ChainAlg::ENCRYPT,
        //     VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
        //     VIRTIO_CRYPTO_SYM_HASH_MODE_PLAIN,
        //     VIRTIO_CRYPTO_HASH_SHA1,
        //     VIRTIO_CRYPTO_CIPHER_AES_CBC,
        // );
        // let encrypt_then_hash_result = chain_alg.encrypt_then_hash(&device, &cipher_key, &[], &iv, &data);
        // early_println!("Result for encrypt then hash: ");
        // early_println!("{:?}", encrypt_then_hash_result);

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