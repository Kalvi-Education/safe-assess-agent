//! Virtual-machine observation (D10). Reports one grouped finding; vendor strings stay local.

use crate::probes::Finding;

// SMBIOS SystemManufacturer / SystemProductName substrings, lowercase.
const VM_FIRMWARE: &[&str] = &[
    "vmware",
    "virtualbox",
    "innotek",
    "qemu",
    "kvm",
    "xen",
    "parallels",
    "google compute engine",
    "amazon ec2",
    "bochs",
    "virtual machine",
];

// CPUID 0x40000000 vendors. "Microsoft Hv" is excluded: Hyper-V/VBS sets it on ordinary
// laptops, so a Hyper-V guest is identified only by firmware ("Virtual Machine").
const VM_HYPERVISORS: &[&str] = &[
    "VMwareVMware",
    "VBoxVBoxVBox",
    "KVMKVMKVM",
    "XenVMMXenVMM",
    "prl hyperv",
    " lrpepyh vr",
    "TCGTCGTCGTCG",
    "bhyve bhyve",
    "QNXQVMBSQG",
];

pub fn is_virtual_machine(firmware: &[&str], hypervisor: Option<&str>) -> bool {
    firmware.iter().any(|value| {
        let value = value.to_ascii_lowercase();
        VM_FIRMWARE.iter().any(|marker| value.contains(marker))
    }) || hypervisor.is_some_and(|vendor| VM_HYPERVISORS.contains(&vendor.trim_end_matches('\0')))
}

pub fn finding(virtual_machine: bool) -> Option<Finding> {
    virtual_machine.then(|| Finding {
        id: "environment:virtual-machine".into(),
        category: "unverified",
        label: "Running inside a virtual machine".into(),
        process_count: None,
        display_count: None,
        window_count: None,
    })
}

#[cfg(target_os = "windows")]
pub fn scan() -> bool {
    use windows::{
        core::{w, PCWSTR},
        Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ},
    };
    let read = |name: PCWSTR| {
        let mut buffer = [0u16; 256];
        let mut size = std::mem::size_of_val(&buffer) as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                w!("HARDWARE\\DESCRIPTION\\System\\BIOS"),
                name,
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut size),
            )
        };
        (status.is_ok()).then(|| {
            let length = (size as usize / 2).saturating_sub(1).min(buffer.len());
            String::from_utf16_lossy(&buffer[..length])
        })
    };
    let firmware: Vec<String> = [w!("SystemManufacturer"), w!("SystemProductName")]
        .into_iter()
        .filter_map(read)
        .collect();
    let firmware: Vec<&str> = firmware.iter().map(String::as_str).collect();
    is_virtual_machine(&firmware, hypervisor_vendor().as_deref())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
// `__cpuid` became safe in recent Rust; keep `unsafe` for older toolchains.
#[allow(unused_unsafe)]
fn hypervisor_vendor() -> Option<String> {
    use std::arch::x86_64::__cpuid;
    // Leaf 1 ECX bit 31: hypervisor present. Vendor leaf is only meaningful when set.
    if unsafe { __cpuid(1) }.ecx & (1 << 31) == 0 {
        return None;
    }
    let leaf = unsafe { __cpuid(0x4000_0000) };
    let bytes: Vec<u8> = [leaf.ebx, leaf.ecx, leaf.edx]
        .iter()
        .flat_map(|register| register.to_le_bytes())
        .collect();
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
fn hypervisor_vendor() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
pub fn scan() -> bool {
    extern "C" {
        fn sysctlbyname(
            name: *const std::ffi::c_char,
            old: *mut std::ffi::c_void,
            old_length: *mut usize,
            new: *const std::ffi::c_void,
            new_length: usize,
        ) -> i32;
    }
    let mut present = 0i32;
    let mut length = size_of::<i32>();
    // kern.hv_vmm_present is 1 inside a VM guest and 0 (or absent) on physical Macs.
    let status = unsafe {
        sysctlbyname(
            c"kern.hv_vmm_present".as_ptr(),
            (&mut present as *mut i32).cast(),
            &mut length,
            std::ptr::null(),
            0,
        )
    };
    status == 0 && present == 1
}

#[cfg(target_os = "linux")]
pub fn scan() -> bool {
    let read = |name: &str| std::fs::read_to_string(format!("/sys/class/dmi/id/{name}")).ok();
    let values: Vec<String> = ["sys_vendor", "product_name", "board_vendor", "bios_vendor"]
        .iter()
        .filter_map(|name| read(name))
        .map(|value| value.trim().to_owned())
        .collect();
    let firmware: Vec<&str> = values.iter().map(String::as_str).collect();
    // The generic CPU "hypervisor" flag is not used alone: it is set on hosts running a
    // hypervisor too. Vendor names are the signal; absent DMI is "unknown", not a VM.
    is_virtual_machine(&firmware, None)
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub fn scan() -> bool {
    false
}
