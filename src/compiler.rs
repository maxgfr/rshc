use std::process::Command;

use anyhow::Result;

/// Derive cross-compiler prefix from a Rust target triple.
/// e.g. "x86_64-unknown-linux-musl" → "x86_64-linux-musl"
fn cross_prefix(target: &str) -> String {
    // Remove "unknown-" segment if present
    target.replace("unknown-", "")
}

/// Append space-separated flags as individual arguments to a Command.
fn add_flags(cmd: &mut Command, flags: &str) {
    for flag in flags.split_whitespace() {
        cmd.arg(flag);
    }
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
            "-static".to_string()
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

    // Remove existing output file if present (avoids permission/linker errors on overwrite)
    if std::path::Path::new(&out).exists() {
        if let Err(e) = std::fs::remove_file(&out) {
            eprintln!("rshc: warning: could not remove existing {}: {}", out, e);
        }
    }

    // Build compilation command using safe argument passing (no shell interpolation)
    let mut cmd = Command::new(&cc);
    add_flags(&mut cmd, &cflags);
    add_flags(&mut cmd, &extra_cflags);
    add_flags(&mut cmd, &ldflags);
    cmd.arg(&c_file).arg("-o").arg(&out);

    if verbose {
        eprintln!(
            "rshc: {} {}{} {} {} -o {}",
            cc, cflags, extra_cflags, ldflags, c_file, out
        );
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("compilation failed");
    }

    // Strip (best-effort, don't fail the build)
    if verbose {
        eprintln!("rshc: {} {}", strip_cmd, out);
    }
    match Command::new(&strip_cmd).arg(&out).status() {
        Ok(status) if !status.success() => {
            eprintln!("rshc: strip failed (non-zero exit), continuing without stripping");
        }
        Err(e) => {
            eprintln!("rshc: strip not available ({}), continuing", e);
        }
        _ => {}
    }

    // Set permissions: ug=rwx,o=rx (0o775) using Rust API instead of shell
    use std::os::unix::fs::PermissionsExt;
    if verbose {
        eprintln!("rshc: chmod 0775 {}", out);
    }
    if let Err(e) = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o775)) {
        eprintln!("rshc: could not set permissions: {}", e);
    }

    Ok(())
}
