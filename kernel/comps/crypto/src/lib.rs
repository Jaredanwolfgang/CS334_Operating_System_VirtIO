//! The crypto device.
#![no_std]
#![deny(unsafe_code)]
#![feature(fn_traits)]
extern crate alloc;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use component::{init_component, ComponentInitError};
use ostd::sync::SpinLock;
use spin::Once;

pub trait AnyCryptoDevice: Send + Sync {
    fn cipher_encrypt(&self, data: &[u8], cipher_key: &[u8]) -> Vec<u8>;
    fn cipher_decrypt(&self, data: &[u8], cipher_key: &[u8]) -> Vec<u8>;
}

pub fn register_device(name: String, device: Arc<dyn AnyCryptoDevice>) {
    COMPONENT
        .get()
        .unwrap()
        .crypto_device_table
        .disable_irq()
        .lock()
        .insert(name, device);
}

pub fn get_device(name: &str) -> Option<Arc<dyn AnyCryptoDevice>> {
    let crypto_devs = COMPONENT
        .get()
        .unwrap()
        .crypto_device_table
        .disable_irq()
        .lock();
    crypto_devs.get(name).map(|device| device.clone())
}

pub fn all_devices() -> Vec<(String, Arc<dyn AnyCryptoDevice>)> {
    let crypto_devs = COMPONENT
        .get()
        .unwrap()
        .crypto_device_table
        .disable_irq()
        .lock();
    crypto_devs
        .iter()
        .map(|(name, device)| (name.clone(), device.clone()))
        .collect()
}

static COMPONENT: Once<Component> = Once::new();

#[init_component]
fn component_init() -> Result<(), ComponentInitError> {
    let a = Component::init()?;
    COMPONENT.call_once(|| a);
    Ok(())
}
struct Component {
    crypto_device_table: SpinLock<BTreeMap<String, Arc<dyn AnyCryptoDevice>>>,
}

impl Component {
    pub fn init() -> Result<Self, ComponentInitError> {
        Ok(Self {
            crypto_device_table: SpinLock::new(BTreeMap::new()),
        })
    }
}