use std::io::{self, Write};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "--version" => {
            println!("safeagent {}", safeagent::VERSION);
            return Ok(());
        }
        [command] if command == "check" => {
            let reply = safeagent::check();
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, &reply)?;
            writeln!(stdout)?;
            if !reply.ok {
                return Err(
                    "CLI check is metadata-only; observations require protocol v2 authorization"
                        .into(),
                );
            }
            return Ok(());
        }
        _ => {}
    }
    let native_args = if args.first().is_some_and(|arg| arg == "messaging") {
        &args[1..]
    } else {
        &args[..]
    };
    let origin =
        match native_args {
            [origin] => origin,
            // Chrome on Windows supplies its parent-window handle as a second argument.
            [origin, parent]
                if cfg!(target_os = "windows")
                    && parent
                        .strip_prefix("--parent-window=")
                        .is_some_and(|value| {
                            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                        }) =>
            {
                origin
            }
            _ => return Err(
                "Usage: safeagent --version | check | messaging chrome-extension://APPROVED_ID/"
                    .into(),
            ),
        };
    if !safeagent::approved_origin(origin) {
        return Err("Native messaging origin is not in the compiled extension allowlist".into());
    }
    safeagent::messaging(&mut io::stdin().lock(), &mut io::stdout().lock())?;
    Ok(())
}

/// Append one line per launch outcome. Chrome discards stderr, so this is the only trace a
/// student or support can read. Codes only: no origins, findings, paths or user data.
fn log_outcome(outcome: &str) {
    use std::fs::OpenOptions;
    let dir = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA")
            .map(|base| std::path::PathBuf::from(base).join("Kalvium/SafeAgent"))
    } else {
        std::env::var_os("HOME")
            .map(|home| std::path::PathBuf::from(home).join("Library/Logs/Kalvium"))
    };
    let Some(dir) = dir else { return };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("safeagent.log");
    // Keep the log bounded; one rotation is enough for support.
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() > 256 * 1024) {
        let _ = std::fs::rename(&path, dir.join("safeagent.log.1"));
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{seconds} v{} {outcome}", safeagent::VERSION);
    }
}

fn main() {
    match run() {
        Ok(()) => log_outcome("exit ok"),
        Err(error) => {
            let code = if error.to_string().contains("allowlist") {
                "origin_rejected"
            } else if error.to_string().starts_with("Usage") {
                "bad_arguments"
            } else {
                "error"
            };
            log_outcome(&format!("exit {code}"));
            eprintln!("safeagent: {error}");
            std::process::exit(1);
        }
    }
}
