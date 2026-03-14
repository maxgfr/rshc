use std::io::{BufWriter, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{bail, Result};

use rshc::payload::{
    Payload, FLAG_BUSYBOX, FLAG_DEBUGEXEC, FLAG_EXT_AES, FLAG_EXT_BIND_HOST, FLAG_EXT_CHACHA,
    FLAG_EXT_COMPRESSED, FLAG_EXT_NO_NETWORK, FLAG_EXT_PASSWORD, FLAG_EXT_STDIN_MODE,
    FLAG_HARDENING, FLAG_MMAP2, FLAG_SETUID, FLAG_TRACEABLE,
};
use rshc::security;

use crate::codegen::{CodegenOptions, EncryptedScript};

/// Extended options for native mode (V2 features).
pub struct NativeOptions {
    pub aes: bool,
    pub chacha: bool,
    pub password: bool,
    pub compress: bool,
    pub stdin_mode: bool,
    pub max_runs: u32,
    pub no_network: bool,
    pub bind_host: bool,
}

/// Find the rshc-runner binary alongside the current executable.
/// Resolves symlinks (Homebrew installs via symlinks) and returns the canonical path.
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
    // Resolve symlinks to get the real path (Homebrew uses symlinks from /opt/homebrew/bin/)
    let resolved = runner
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("rshc: cannot resolve {}: {}", runner.display(), e))?;
    Ok(resolved)
}

/// Pre-process script text before encryption: compress, then AES-encrypt.
/// Returns (processed_text, aes_key, aes_nonce).
/// These transformations happen BEFORE RC4 encryption so the RC4 stream is consistent.
pub fn preprocess_text(
    text: &[u8],
    native_opts: &NativeOptions,
    verbose: bool,
) -> Result<(Vec<u8>, [u8; 32], [u8; 12])> {
    let mut processed = text.to_vec();
    let mut aes_key = [0u8; 32];
    let mut aes_nonce = [0u8; 12];

    // Step 1: Compress (before AES, so runner decompresses after AES-decrypt)
    if native_opts.compress {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;

        let original_len = processed.len();
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&processed)?;
        processed = encoder.finish()?;

        if verbose {
            eprintln!(
                "rshc: compression: {} -> {} bytes ({:.1}%)",
                original_len,
                processed.len(),
                (1.0 - processed.len() as f64 / original_len as f64) * 100.0
            );
        }
    }

    // Step 2: AEAD encrypt (on top of compressed data, before RC4)
    if native_opts.aes {
        rand::Rng::fill(&mut rand::rngs::OsRng, &mut aes_key);
        let (ciphertext, nonce) =
            rshc::aes::aes_encrypt(&processed, &aes_key).map_err(|e| anyhow::anyhow!("{}", e))?;
        processed = ciphertext;
        aes_nonce = nonce;
    } else if native_opts.chacha {
        rand::Rng::fill(&mut rand::rngs::OsRng, &mut aes_key);
        let (ciphertext, nonce) = rshc::chacha::chacha_encrypt(&processed, &aes_key)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        processed = ciphertext;
        aes_nonce = nonce;
    }

    Ok((processed, aes_key, aes_nonce))
}

/// Build a native binary by copying the runner stub and appending the encrypted payload.
#[allow(clippy::too_many_arguments)]
pub fn build_native(
    encrypted: &EncryptedScript,
    options: &CodegenOptions,
    native_opts: &NativeOptions,
    aes_key: &[u8; 32],
    aes_nonce: &[u8; 12],
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

    // Build extended flags
    let mut ext_flags: u8 = 0;
    if native_opts.aes {
        ext_flags |= FLAG_EXT_AES;
    }
    if native_opts.chacha {
        ext_flags |= FLAG_EXT_CHACHA;
    }
    if native_opts.password {
        ext_flags |= FLAG_EXT_PASSWORD;
    }
    if native_opts.compress {
        ext_flags |= FLAG_EXT_COMPRESSED;
    }
    if native_opts.stdin_mode {
        ext_flags |= FLAG_EXT_STDIN_MODE;
    }
    if native_opts.no_network {
        ext_flags |= FLAG_EXT_NO_NETWORK;
    }
    if native_opts.bind_host {
        ext_flags |= FLAG_EXT_BIND_HOST;
    }

    // Handle password and/or bind-host
    let mut password_salt = [0u8; 32];
    let mut password_hash = [0u8; 32];

    // If bind-host without password, store machine identity in password_salt
    if native_opts.bind_host && !native_opts.password {
        password_salt = security::get_machine_identity();
        if verbose {
            eprintln!("rshc: host identity bound to binary");
        }
    }

    if native_opts.password {
        let pass = security::read_password("Enter password: ")?;
        let pass_confirm = security::read_password("Confirm password: ")?;
        if pass != pass_confirm {
            bail!("rshc: passwords do not match");
        }
        if pass.is_empty() {
            bail!("rshc: password cannot be empty");
        }
        rand::Rng::fill(&mut rand::rngs::OsRng, &mut password_salt);
        password_hash = security::hash_password(pass.as_bytes(), &password_salt);
    }

    // Store AEAD key in the pswd array for transport (first 32 bytes)
    let pswd = if native_opts.aes || native_opts.chacha {
        let mut extended = aes_key.to_vec();
        extended.extend_from_slice(&encrypted.pswd);
        extended
    } else {
        encrypted.pswd.clone()
    };

    let payload = Payload {
        flags,
        relax_was_zero: encrypted.relax_was_zero,
        arrays: [
            pswd,
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
        ext_flags,
        password_salt,
        password_hash,
        aes_nonce: *aes_nonce,
        max_runs: native_opts.max_runs,
        ..Default::default()
    };

    // Remove existing output file if present (avoids permission errors on overwrite)
    if std::path::Path::new(&out).exists() {
        std::fs::remove_file(&out)
            .map_err(|e| anyhow::anyhow!("rshc: removing existing {}: {}", out, e))?;
    }

    // Copy runner binary to output
    std::fs::copy(&runner_path, &out)
        .map_err(|e| anyhow::anyhow!("rshc: copying runner to {}: {}", out, e))?;

    // Set restrictive permissions during build (owner-only) to prevent reads during construction
    #[cfg(unix)]
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| anyhow::anyhow!("rshc: setting permissions on {}: {}", out, e))?;

    // Compute integrity hash of the runner binary (before payload append)
    let integrity_hash = security::hash_file(std::path::Path::new(&out))
        .map_err(|e| anyhow::anyhow!("rshc: hashing runner binary: {}", e))?;

    // We need to set the integrity hash in the payload. Since Payload doesn't have
    // interior mutability, create a new payload with the hash.
    let payload = Payload {
        integrity_hash,
        ..payload
    };

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

    // Set final permissions
    #[cfg(unix)]
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o775))
        .map_err(|e| anyhow::anyhow!("rshc: setting permissions on {}: {}", out, e))?;

    if verbose {
        eprintln!("rshc: native binary written to {}", out);
        if native_opts.aes {
            eprintln!("rshc: AES-256-GCM encryption enabled");
        }
        if native_opts.chacha {
            eprintln!("rshc: ChaCha20-Poly1305 encryption enabled");
        }
        if native_opts.compress {
            eprintln!("rshc: compression enabled");
        }
        if native_opts.password {
            eprintln!("rshc: password protection enabled");
        }
        if native_opts.stdin_mode {
            eprintln!("rshc: stdin mode enabled");
        }
        if native_opts.no_network {
            eprintln!("rshc: network isolation enabled");
        }
        if native_opts.bind_host {
            eprintln!("rshc: host binding enabled");
        }
        if native_opts.max_runs > 0 {
            eprintln!("rshc: max runs: {}", native_opts.max_runs);
        }
    }

    Ok(())
}
