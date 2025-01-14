use core::mem::offset_of;

use aster_util::safe_ptr::SafePtr;
use ostd::Pod;

use crate::transport::{ConfigManager, VirtioTransport};

bitflags::bitflags! {
    pub struct CryptoFeatures: u64{
        /// revision 1.
        /// Revision 1 has a specific request format and other enhancements (which result in some additional requirements).
        /// 这里的其他所有feature bits都需要revision 1特性.
        const VIRTIO_CRYPTO_F_REVISION_1 = 1 << 0;
        /// stateless mode requests are supported by the CIPHER service.
        const VIRTIO_CRYPTO_F_CIPHER_STATELESS_MODE = 1 << 1;
        /// stateless mode requests are supported by the HASH service.
        const VIRTIO_CRYPTO_F_HASH_STATELESS_MODE = 1 << 2;
        /// stateless mode requests are supported by the MAC service.
        const VIRTIO_CRYPTO_F_MAC_STATELESS_MODE = 1 << 3;
        /// stateless mode requests are supported by the AEAD service.
        const VIRTIO_CRYPTO_F_AEAD_STATELESS_MODE = 1 << 4;
        /// stateless mode requests are supported by the AKCIPHER service.
        const VIRTIO_CRYPTO_F_AKCIPHER_STATELESS_MODE = 1 << 5;

    }
}

#[derive(Debug, Pod, Clone, Copy)]
// repr(c)使该结构体的内存布局与C兼容
#[repr(C)]
pub struct VirtioCryptoConfig {
    pub status: u32,
    // 设备支持的data virtqueue的最大数量
    // 驱动可能只使用1个data virtqueue，也可以使用多个（带来性能提升）
    pub max_dataqueues: u32,
    // 支持的加密算法包
    pub crypto_services: u32,
    /// 下面这些内容描述了各包中具体支持的算法，l和h表示low(0-31)和high(32-63)两部分，共同组成64位特性
    pub cipher_algo_l: u32,
    pub cipher_algo_h: u32,
    pub hash_algo: u32,
    pub mac_algo_l: u32,
    pub mac_algo_h: u32,
    pub aead_algo: u32,
    // Maximum length of cipher key in bytes
    pub max_cipher_key_len: u32,
    // Maximum length of authenticated key in bytes
    pub max_auth_key_len: u32,
    pub akcipher_algo: u32,
    // Maximum size of each crypto request's content in bytes
    // TODO: 实际上是u64
    pub max_size: u32,
}

impl VirtioCryptoConfig {
    pub(super) fn new_manager(transport: &dyn VirtioTransport) -> ConfigManager<Self> {
        let safe_ptr = transport
            .device_config_mem()
            .map(|mem| SafePtr::new(mem, 0));
        let bar_space = transport.device_config_bar();
        ConfigManager::new(safe_ptr, bar_space)
    }
}

impl ConfigManager<VirtioCryptoConfig> {
    pub(super) fn read_config(&self) -> VirtioCryptoConfig {
        let mut crypto_config = VirtioCryptoConfig::new_uninit();
        // status
        crypto_config.status = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, status))
            .unwrap();
        // max_dataqueues
        crypto_config.max_dataqueues = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, max_dataqueues))
            .unwrap();
        // crypto_services
        crypto_config.crypto_services = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, crypto_services))
            .unwrap();
        // cipher_algo_l
        crypto_config.cipher_algo_l = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, cipher_algo_l))
            .unwrap();
        // cipher_algo_h
        crypto_config.cipher_algo_h = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, cipher_algo_h))
            .unwrap();
        // hash_algo
        crypto_config.hash_algo = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, hash_algo))
            .unwrap();
        // mac_algo_l
        crypto_config.mac_algo_l = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, mac_algo_l))
            .unwrap();
        // mac_algo_h
        crypto_config.mac_algo_h = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, mac_algo_h))
            .unwrap();
        // aead_algo
        crypto_config.aead_algo = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, aead_algo))
            .unwrap();
        // max_cipher_key_len
        crypto_config.max_cipher_key_len = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, max_cipher_key_len))
            .unwrap();
        // max_auth_key_len
        crypto_config.max_auth_key_len = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, max_auth_key_len))
            .unwrap();
        // akcipher_algo
        crypto_config.akcipher_algo = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, akcipher_algo))
            .unwrap();
        // max_size
        // TODO: 实际上是u64
        crypto_config.max_size = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, max_size))
            .unwrap();

        crypto_config
    }
}
