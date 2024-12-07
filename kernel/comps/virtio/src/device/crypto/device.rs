use log::debug;
use ostd::mm::{DmaStream, FrameAllocOptions, DmaDirection};
use ostd::sync::SpinLock;
use ostd::early_println;
use alloc::sync::Arc;
use super::config::VirtioCryptoConfig;
use crate::queue::VirtQueue;
use crate::Box;
use crate::VirtioTransport;
use crate::device::VirtioDeviceError;
use crate::transport::ConfigManager;

pub struct CryptoDevice {
    config_manager: ConfigManager<VirtioCryptoConfig>,
    request_buffer: DmaStream,
    request_queue: SpinLock<VirtQueue>,
    transport: SpinLock<Box<dyn VirtioTransport>>,
}

impl CryptoDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        // TODO: 根据设备要求进行功能选择
        features
    }

    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {

        let config_manager = VirtioCryptoConfig::new_manager(transport.as_ref());
        debug!("virtio_crypto_config = {:?}", config_manager.read_config());
        
        // TODO: 初始化设备，下面的代码需要修改

        // 初始化请求队列
        const REQUEST_QUEUE_INDEX: u16 = 0;
        let request_queue = SpinLock::new(VirtQueue::new(REQUEST_QUEUE_INDEX, 1, transport.as_mut()).unwrap());
        
        // 初始化请求缓冲区
        let request_buffer = {
            let vm_segment = FrameAllocOptions::new(1).alloc_contiguous().unwrap();
            DmaStream::map(vm_segment, DmaDirection::FromDevice, false).unwrap()
        };

        // 创建设备实例
        let device = Arc::new(
            Self {
                config_manager,
                request_buffer,
                request_queue,
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
    // 输出设备信息
    early_println!("virtio_crypto_config = {:?}", device.config_manager.read_config());
    // TODO: 需要补充测试代码
}
