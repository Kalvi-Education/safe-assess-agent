//! Test-only harness for VM suite S2 cases 2.7 / 2.8. Never packaged or shipped.
//!
//! Build: cargo build --example overlay-harness --target x86_64-pc-windows-msvc --release
//! Run:   overlay-harness.exe [capture|noactivate|both]   (default both; close windows to exit)
//!
//! capture     a normal visible window with WDA_EXCLUDEFROMCAPTURE (expect overlay:sharing-restricted)
//! noactivate  a topmost WS_EX_NOACTIVATE tool window (expect overlay:no-activate)

#[cfg(target_os = "windows")]
fn main() {
    use windows::{
        core::{w, PCWSTR},
        Win32::{
            Foundation::{HWND, LPARAM, LRESULT, WPARAM},
            System::LibraryLoader::GetModuleHandleW,
            UI::WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, PostQuitMessage,
                RegisterClassW, SetWindowDisplayAffinity, ShowWindow, TranslateMessage, MSG,
                SW_SHOWNOACTIVATE, WDA_EXCLUDEFROMCAPTURE, WINDOW_EX_STYLE, WM_DESTROY, WNDCLASSW,
                WS_CAPTION, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW,
                WS_POPUP, WS_VISIBLE,
            },
        },
    };

    static mut OPEN: u32 = 0;
    unsafe extern "system" fn procedure(
        window: HWND,
        message: u32,
        w: WPARAM,
        l: LPARAM,
    ) -> LRESULT {
        if message == WM_DESTROY {
            unsafe {
                OPEN -= 1;
                if OPEN == 0 {
                    PostQuitMessage(0);
                }
            }
            return LRESULT(0);
        }
        unsafe { DefWindowProcW(window, message, w, l) }
    }

    let mode = std::env::args().nth(1).unwrap_or_else(|| "both".into());
    let instance = unsafe { GetModuleHandleW(None) }.expect("module handle");
    let class = WNDCLASSW {
        lpfnWndProc: Some(procedure),
        hInstance: instance.into(),
        lpszClassName: w!("SafeAgentOverlayHarness"),
        ..Default::default()
    };
    assert!(
        unsafe { RegisterClassW(&class) } != 0,
        "RegisterClassW failed"
    );

    let create = |ex: WINDOW_EX_STYLE, title: PCWSTR, style, x| unsafe {
        let window = CreateWindowExW(
            ex,
            class.lpszClassName,
            title,
            style,
            x,
            120,
            420,
            220,
            None,
            None,
            instance,
            None,
        );
        assert!(window.0 != 0, "CreateWindowExW failed");
        OPEN += 1;
        window
    };

    if mode == "capture" || mode == "both" {
        let window = create(
            WINDOW_EX_STYLE(0),
            w!("SafeAgent harness: hidden from capture"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            120,
        );
        unsafe { SetWindowDisplayAffinity(window, WDA_EXCLUDEFROMCAPTURE) }
            .expect("SetWindowDisplayAffinity (needs Windows 10 2004+)");
        println!("capture-excluded window open");
    }
    if mode == "noactivate" || mode == "both" {
        let window = create(
            WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            w!("SafeAgent harness: no-activate overlay"),
            WS_POPUP | WS_CAPTION,
            600,
        );
        unsafe {
            let _ = ShowWindow(window, SW_SHOWNOACTIVATE);
        }
        println!("topmost no-activate window open");
    }

    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.as_bool() {
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("overlay-harness is Windows-only");
    std::process::exit(2);
}
