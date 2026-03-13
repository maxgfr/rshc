use std::io::{BufWriter, Write};
use std::os::unix::fs::PermissionsExt;

use anyhow::{bail, Result};

use rshc::payload::{
    Payload, FLAG_BUSYBOX, FLAG_DEBUGEXEC, FLAG_HARDENING, FLAG_MMAP2, FLAG_SETUID, FLAG_TRACEABLE,
};

use crate::codegen::{CodegenOptions, EncryptedScript};

/// Find the rshc-runner binary alongside the current executable.
fn find_runner() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("rshc: cannot find own executable: {}", e))?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rshc: cannot determine executable directory"))?;
    let runner = dir.join("rshc-runner");
    if !runner.exists() {
        bail!(
            "rshc: rshc-runner not found at {} (is it installed?)",
            runner.display()
        );
    }
    Ok(runner)
}

/// Build a native binary by copying the runner stub and appending the encrypted payload.
pub fn build_native(
    encrypted: &EncryptedScript,
    options: &CodegenOptions,
    file: &str,
    outfile: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let runner_path = find_runner()?;
    let out = match outfile {
        Some(o) => o.to_string(),
        None => format!("{}.x", file),
    };

    if verbose {
        eprintln!(
            "rshc: native mode: runner={} output={}",
            runner_path.display(),
            out
        );
    }

    // Build flags byte
    let mut flags: u8 = 0;
    if options.setuid {
        flags |= FLAG_SETUID;
    }
    if options.debugexec {
        flags |= FLAG_DEBUGEXEC;
    }
    if options.traceable {
        flags |= FLAG_TRACEABLE;
    }
    if options.hardening {
        flags |= FLAG_HARDENING;
    }
    if options.busybox {
        flags |= FLAG_BUSYBOX;
    }
    if options.mmap2 {
        flags |= FLAG_MMAP2;
    }

    let payload = Payload {
        flags,
        relax_was_zero: encrypted.relax_was_zero,
        arrays: [
            encrypted.pswd.clone(),
            encrypted.msg1.clone(),
            encrypted.date.clone(),
            encrypted.shll.clone(),
            encrypted.inlo.clone(),
            encrypted.xecc.clone(),
            encrypted.lsto.clone(),
            encrypted.tst1.clone(),
            encrypted.chk1.clone(),
            encrypted.msg2.clone(),
            encrypted.rlax.clone(),
            encrypted.opts.clone(),
            encrypted.text.clone(),
            encrypted.tst2.clone(),
            encrypted.chk2.clone(),
        ],
    };

    // Copy runner binary to output
    std::fs::copy(&runner_path, &out)
        .map_err(|e| anyhow::anyhow!("rshc: copying runner to {}: {}", out, e))?;

    // Append payload
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&out)
        .map_err(|e| anyhow::anyhow!("rshc: opening {} for append: {}", out, e))?;

    let mut w = BufWriter::new(&mut f);
    payload
        .serialize(&mut w)
        .map_err(|e| anyhow::anyhow!("rshc: writing payload: {}", e))?;
    w.flush()?;
    drop(w);
    drop(f);

    // Set permissions
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o775))
        .map_err(|e| anyhow::anyhow!("rshc: setting permissions on {}: {}", out, e))?;

    if verbose {
        eprintln!("rshc: native binary written to {}", out);
    }

    Ok(())
}
