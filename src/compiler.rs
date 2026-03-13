use std::process::Command;

use anyhow::Result;

/// Derive cross-compiler prefix from a Rust target triple.
/// e.g. "x86_64-unknown-linux-musl" → "x86_64-linux-musl"
fn cross_prefix(target: &str) -> String {
    // Remove "unknown-" segment if present
    target.replace("unknown-", "")
}

/// Compile, strip, and chmod the generated C file.
/// Matches make() in shc.c:1300-1338.
/// If `target` is provided, uses a cross-compiler derived from the target triple.
pub fn make(file: &str, outfile: Option<&str>, verbose: bool, target: Option<&str>) -> Result<()> {
    let (cc, strip_cmd, extra_cflags) = if let Some(t) = target {
        let prefix = cross_prefix(t);
        let cc = std::env::var("CC").unwrap_or_else(|_| format!("{}-gcc", prefix));
        let strip = std::env::var("STRIP").unwrap_or_else(|_| format!("{}-strip", prefix));
        let extra = if t.contains("musl") {
            " -static".to_string()
        } else {
            String::new()
        };
        (cc, strip, extra)
    } else {
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let strip = std::env::var("STRIP").unwrap_or_else(|_| "strip".to_string());
        (cc, strip, String::new())
    };

    let cflags = std::env::var("CFLAGS").unwrap_or_default();
    let ldflags = std::env::var("LDFLAGS").unwrap_or_default();

    let out = match outfile {
        Some(o) => o.to_string(),
        None => format!("{}.x", file),
    };

    let c_file = format!("{}.x.c", file);
    let cmd = format!(
        "{} {}{} {} {} -o {}",
        cc, cflags, extra_cflags, ldflags, c_file, out
    );
    if verbose {
        eprintln!("rshc: {}", cmd);
    }
    let status = Command::new("sh").arg("-c").arg(&cmd).status()?;
    if !status.success() {
        anyhow::bail!("compilation failed");
    }

    // Strip (ignore failure)
    let cmd = format!("{} {}", strip_cmd, out);
    if verbose {
        eprintln!("rshc: {}", cmd);
    }
    if let Ok(status) = Command::new("sh").arg("-c").arg(&cmd).status() {
        if !status.success() {
            eprintln!("rshc: never mind");
        }
    }

    // chmod (ignore failure)
    let cmd = format!("chmod ug=rwx,o=rx {}", out);
    if verbose {
        eprintln!("rshc: {}", cmd);
    }
    if let Ok(status) = Command::new("sh").arg("-c").arg(&cmd).status() {
        if !status.success() {
            eprintln!("rshc: remove read permission");
        }
    }

    Ok(())
}
