use log::debug;
use ostd::mm::{DmaStream, FrameAllocOptions, DmaDirection};
use ostd::sync::SpinLock;
use ostd::early_println;
use alloc::sync::Arc;
use alloc::vec::Vec;
use super::config::VirtioCryptoConfig;
use crate::queue::VirtQueue;
use crate::Box;
use crate::VirtioTransport;
use crate::device::VirtioDeviceError;

pub struct CryptoDevice {
    pub config: VirtioCryptoConfig,
    pub dataqs: Vec<SpinLock<VirtQueue>>,
    pub controlq: SpinLock<VirtQueue>,
    pub transport: SpinLock<Box<dyn VirtioTransport>>,
}

impl CryptoDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        // TODO: 根据设备要求进行功能选择
        features
    }

    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {

        let config_manager = VirtioCryptoConfig::new_manager(transport.as_ref());
        let config = config_manager.read_config();
        debug!("virtio_crypto_config = {:?}", config);
        
        // 初始化设备，下面的代码需要修改
        // 创建数据队列 (dataq)
        let mut dataqs = Vec::with_capacity(config.max_dataqueues as usize);
        
        // TODO: DATAQ_SIZE未知，暂且设置为1
        let DATAQ_SIZE = 1;

        for dataq_index in 0..config.max_dataqueues {
            // TODO: config.max_dataqueues为u32类型，但VirtQueue::new()中接收的idx数据为u16，范围小于max_dataqueues
            // 这里强行将u32转换成u16，如果max_dataqueues的数据内容大于u16将导致BUG
            let DATAQ_INDEX = dataq_index as u16;
            let dataq = SpinLock::new(VirtQueue::new(DATAQ_INDEX, DATAQ_SIZE, transport.as_mut()).unwrap());
            dataqs.push(dataq);
        }

        // TODO: CONTROLQ_SIZE未知，暂且设置为1
        let CONTROLQ_SIZE = 1;
        // TODO: 同上，强行转换为u16，可能导致BUG
        let CONTROLQ_INDEX = config.max_dataqueues as u16;
        let controlq = SpinLock::new(VirtQueue::new(CONTROLQ_INDEX, CONTROLQ_SIZE, transport.as_mut()).unwrap());

        // 创建设备实例
        let device = Arc::new(
            Self {
                config,
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
    // 输出设备信息
    early_println!("virtio_crypto_config = {:#?}", device.config);
    // TODO: 需要补充测试代码
}
