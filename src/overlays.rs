use crate::probes::{Capability, Finding, Status};

pub const LIMITATION: &str = "Visible window metadata only, not proof of assistance or capture exclusion. System UI and legitimate utilities can match; hidden windows, other desktops and inaccessible metadata may be missed. No titles, owners, PIDs or images are returned. macOS sharing state does not establish modern capture behavior; Windows capture affinity is not inspected.";

#[derive(Default)]
pub struct Observations {
    pub scanned: usize,
    pub elevated: usize,
    pub restricted: usize,
    pub incomplete: bool,
}

impl Observations {
    pub fn mac_window(&mut self, layer: Option<i64>, sharing: Option<i64>) {
        self.scanned += 1;
        match layer {
            Some(layer) if layer > 0 => self.elevated += 1,
            Some(_) => {}
            None => self.incomplete = true,
        }
        match sharing {
            Some(0) => self.restricted += 1,
            Some(1 | 2) => {}
            _ => self.incomplete = true,
        }
    }

    pub fn windows_window(&mut self, visible: bool, style: Option<u32>) {
        if !visible {
            return;
        }
        self.scanned += 1;
        match style {
            // WS_EX_TOPMOST combined with WS_EX_LAYERED or WS_EX_TRANSPARENT.
            Some(style) if style & 0x8 != 0 && style & (0x80000 | 0x20) != 0 => self.elevated += 1,
            Some(_) => {}
            None => self.incomplete = true,
        }
    }
}

pub fn apply(
    result: Result<Observations, &'static str>,
    capability: &mut Capability,
    findings: &mut Vec<Finding>,
) {
    let observations = match result {
        Ok(observations) => observations,
        Err(message) => {
            capability.status = Status::Error;
            capability.limitation = message;
            return;
        }
    };
    capability.status = if observations.incomplete || observations.scanned == 0 {
        Status::Error
    } else {
        Status::Available
    };
    capability.limitation = if capability.status == Status::Error {
        "Window metadata was incomplete or no visible windows were enumerated; overlay state is unknown. Permissions, window lifecycle and desktop/session access can limit coverage. Partial observations are not proof of assistance or capture exclusion."
    } else {
        LIMITATION
    };
    for (id, label, count) in [
        (
            "overlay:elevated-window",
            "Potential overlay window properties",
            observations.elevated,
        ),
        (
            "overlay:sharing-restricted",
            "Windows reporting restricted sharing metadata",
            observations.restricted,
        ),
    ] {
        if count > 0 {
            findings.push(Finding {
                id: id.into(),
                category: "overlay",
                label: label.to_string(),
                process_count: None,
                display_count: None,
                window_count: Some(count),
            });
        }
    }
}

#[cfg(target_os = "macos")]
pub fn scan() -> Result<Observations, &'static str> {
    use std::ffi::c_void;
    type Ref = *const c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGWindowListCopyWindowInfo(options: u32, relative: u32) -> Ref;
        static kCGWindowLayer: Ref;
        static kCGWindowSharingState: Ref;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(value: Ref);
        fn CFArrayGetCount(array: Ref) -> isize;
        fn CFArrayGetValueAtIndex(array: Ref, index: isize) -> Ref;
        fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
        fn CFGetTypeID(value: Ref) -> usize;
        fn CFDictionaryGetTypeID() -> usize;
        fn CFNumberGetTypeID() -> usize;
        fn CFNumberGetValue(number: Ref, kind: isize, output: *mut c_void) -> bool;
    }
    unsafe fn number(dictionary: Ref, key: Ref) -> Option<i64> {
        let value = unsafe { CFDictionaryGetValue(dictionary, key) };
        if value.is_null() || unsafe { CFGetTypeID(value) != CFNumberGetTypeID() } {
            return None;
        }
        let mut result = 0i64;
        // kCFNumberSInt64Type = 4. Never read title/owner fields.
        if unsafe { CFNumberGetValue(value, 4, (&mut result as *mut i64).cast()) } {
            Some(result)
        } else {
            None
        }
    }
    // On-screen only; deliberately retain system/desktop windows rather than
    // blanket owner exclusions. Metadata retrieval never requests screen capture.
    let list = unsafe { CGWindowListCopyWindowInfo(1, 0) };
    if list.is_null() {
        return Err("CoreGraphics window enumeration failed; session or permission access may be unavailable.");
    }
    let mut observations = Observations::default();
    for index in 0..unsafe { CFArrayGetCount(list) } {
        let dictionary = unsafe { CFArrayGetValueAtIndex(list, index) };
        if dictionary.is_null() || unsafe { CFGetTypeID(dictionary) != CFDictionaryGetTypeID() } {
            observations.incomplete = true;
            continue;
        }
        observations.mac_window(unsafe { number(dictionary, kCGWindowLayer) }, unsafe {
            number(dictionary, kCGWindowSharingState)
        });
    }
    unsafe {
        CFRelease(list);
    }
    Ok(observations)
}

#[cfg(target_os = "windows")]
pub fn scan() -> Result<Observations, &'static str> {
    use std::ffi::c_void;
    #[link(name = "user32")]
    extern "system" {
        fn EnumWindows(
            callback: unsafe extern "system" fn(*mut c_void, isize) -> i32,
            data: isize,
        ) -> i32;
        fn IsWindowVisible(window: *mut c_void) -> i32;
        fn GetWindowLongW(window: *mut c_void, index: i32) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn SetLastError(error: u32);
        fn GetLastError() -> u32;
    }
    unsafe extern "system" fn observe(window: *mut c_void, data: isize) -> i32 {
        if unsafe { IsWindowVisible(window) } == 0 {
            return 1;
        }
        unsafe {
            SetLastError(0);
        }
        // GWL_EXSTYLE is a 32-bit value on both x86 and x64.
        let style = unsafe { GetWindowLongW(window, -20) };
        let style = if style == 0 && unsafe { GetLastError() } != 0 {
            None
        } else {
            Some(style as u32)
        };
        unsafe { &mut *(data as *mut Observations) }.windows_window(true, style);
        1
    }
    let mut observations = Observations::default();
    // EnumWindows invokes callbacks synchronously; the context outlives the call.
    let result = unsafe { EnumWindows(observe, (&mut observations as *mut Observations) as isize) };
    if result == 0 {
        Err("Windows top-level window enumeration failed; desktop/session access may be unavailable.")
    } else {
        Ok(observations)
    }
}
