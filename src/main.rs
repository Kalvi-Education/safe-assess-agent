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

fn main() {
    if let Err(error) = run() {
        eprintln!("safeagent: {error}");
        std::process::exit(1);
    }
}
