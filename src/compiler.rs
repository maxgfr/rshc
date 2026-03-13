use std::process::Command;

use anyhow::Result;

/// Compile, strip, and chmod the generated C file.
/// Matches make() in shc.c:1300-1338.
pub fn make(file: &str, outfile: Option<&str>, verbose: bool) -> Result<()> {
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let cflags = std::env::var("CFLAGS").unwrap_or_default();
    let ldflags = std::env::var("LDFLAGS").unwrap_or_default();

    let out = match outfile {
        Some(o) => o.to_string(),
        None => format!("{}.x", file),
    };

    let c_file = format!("{}.x.c", file);
    let cmd = format!("{} {} {} {} -o {}", cc, cflags, ldflags, c_file, out);
    if verbose {
        eprintln!("rshc: {}", cmd);
    }
    let status = Command::new("sh").arg("-c").arg(&cmd).status()?;
    if !status.success() {
        anyhow::bail!("compilation failed");
    }

    // Strip (ignore failure)
    let strip = std::env::var("STRIP").unwrap_or_else(|_| "strip".to_string());
    let cmd = format!("{} {}", strip, out);
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
