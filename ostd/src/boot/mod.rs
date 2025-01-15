// SPDX-License-Identifier: MPL-2.0

//! The architecture-independent boot module, which provides
//!  1. a universal information getter interface from the bootloader to the
//!     rest of OSTD;
//!  2. the routine booting into the actual kernel;
//!  3. the routine booting the other processors in the SMP context.

pub mod memory_region;
pub mod smp;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use memory_region::{MemoryRegion, MemoryRegionArray};
use spin::Once;

/// The boot information provided by the bootloader.
pub struct BootInfo {
    /// The name of the bootloader.
    pub bootloader_name: String,
    /// The kernel command line arguments.
    pub kernel_cmdline: String,
    /// The initial ramfs raw bytes.
    pub initramfs: Option<&'static [u8]>,
    /// The framebuffer arguments.
    pub framebuffer_arg: Option<BootloaderFramebufferArg>,
    /// The memory regions provided by the bootloader.
    pub memory_regions: Vec<MemoryRegion>,
}

/// Gets the boot information.
///
/// This function is usable after initialization with [`init_after_heap`].
pub fn boot_info() -> &'static BootInfo {
    INFO.get().unwrap()
}

static INFO: Once<BootInfo> = Once::new();

/// ACPI information from the bootloader.
///
/// The boot crate can choose either providing the raw RSDP physical address or
/// providing the RSDT/XSDT physical address after parsing RSDP.
/// This is because bootloaders differ in such behaviors.
#[derive(Copy, Clone, Debug)]
pub enum BootloaderAcpiArg {
    /// The bootloader does not provide one, a manual search is needed.
    NotProvided,
    /// Physical address of the RSDP.
    Rsdp(usize),
    /// Address of RSDT provided in RSDP v1.
    Rsdt(usize),
    /// Address of XSDT provided in RSDP v2+.
    Xsdt(usize),
}

/// The framebuffer arguments.
#[derive(Copy, Clone, Debug)]
pub struct BootloaderFramebufferArg {
    /// The address of the buffer.
    pub address: usize,
    /// The width of the buffer.
    pub width: usize,
    /// The height of the buffer.
    pub height: usize,
    /// Bits per pixel of the buffer.
    pub bpp: usize,
}

/*************************** Boot-time information ***************************/

/// The boot-time boot information.
///
/// When supporting multiple boot protocols with a single build, the entrypoint
/// and boot information getters are dynamically decided. The entry point
/// function should initializer all arguments at [`EARLY_INFO`].
///
/// All the references in this structure should be valid in the boot context.
/// After the kernel is booted, users should use [`BootInfo`] instead.
pub(crate) struct EarlyBootInfo {
    pub(crate) bootloader_name: &'static str,
    pub(crate) kernel_cmdline: &'static str,
    pub(crate) initramfs: Option<&'static [u8]>,
    pub(crate) acpi_arg: BootloaderAcpiArg,
    pub(crate) framebuffer_arg: Option<BootloaderFramebufferArg>,
    pub(crate) memory_regions: MemoryRegionArray,
}

/// The boot-time information.
pub(crate) static EARLY_INFO: Once<EarlyBootInfo> = Once::new();

/// Initializes the boot information.
///
/// This function copies the boot-time accessible information to the heap to
/// allow [`boot_info`] to work properly.
pub(crate) fn init_after_heap() {
    let boot_time_info = EARLY_INFO.get().unwrap();

    INFO.call_once(|| BootInfo {
        bootloader_name: boot_time_info.bootloader_name.to_string(),
        kernel_cmdline: boot_time_info.kernel_cmdline.to_string(),
        initramfs: boot_time_info.initramfs,
        framebuffer_arg: boot_time_info.framebuffer_arg,
        memory_regions: boot_time_info.memory_regions.to_vec(),
    });
}

/// Calls the OSTD-user defined entrypoint of the actual kernel.
///
/// Any kernel that uses the `ostd` crate should define a function marked with
/// `ostd::main` as the entrypoint.
///
/// This function should be only called from the bootloader-specific module.
pub(crate) fn call_ostd_main() -> ! {
    // The entry point of kernel code, which should be defined by the package that
    // uses OSTD.
    extern "Rust" {
        fn __ostd_main() -> !;
    }

    // SAFETY: The function is called only once on the BSP.
    unsafe { crate::init() };

    // SAFETY: This external function is defined by the package that uses OSTD,
    // which should be generated by the `ostd::main` macro. So it is safe.
    unsafe {
        __ostd_main();
    }
}
