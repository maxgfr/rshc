//! rshc-runner: Native Rust runtime for rshc-compiled scripts.
//!
//! This binary is used as a stub: rshc copies it and appends an encrypted
//! payload to the end. At runtime, the runner reads the payload from its
//! own executable, decrypts the script, and exec's the target shell.
//!
//! V2 features inspired by chenyukang/rshc (https://github.com/chenyukang/rshc):
//! - Anti-debug detection (ptrace, env injection, TracerPid, timer-based)
//! - Memory zeroing for sensitive data (zeroize)
//! - Stdin piping (hide script from /proc/*/cmdline)
//! - Binary self-integrity check (SHA-256)
//! - AES-256-GCM encryption (on top of RC4)
//! - Password protection (Argon2id hash verification)
//! - Script compression (deflate)
//! - Max execution count (with file locking)
//! - Cross-platform support (Unix + Windows)

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use rshc::payload::{
    self, Payload, FLAG_DEBUGEXEC, FLAG_EXT_AES, FLAG_EXT_BIND_HOST, FLAG_EXT_CHACHA,
    FLAG_EXT_COMPRESSED, FLAG_EXT_NO_NETWORK, FLAG_EXT_PASSWORD, FLAG_EXT_STDIN_MODE, FLAG_SETUID,
    FLAG_TRACEABLE,
};
use rshc::rc4::Rc4;
use rshc::security;

/// XOR obfuscation key for error messages in the binary.
const XOR_KEY: u8 = 0x5A;

/// Get an XOR-obfuscated error message at runtime.
fn obfuscated_msg(encoded: &[u8]) -> String {
    String::from_utf8_lossy(&security::xor_decode(encoded, XOR_KEY)).to_string()
}

fn die(me: &str, msg: &str) -> ! {
    eprintln!("{}: {}", me, msg);
    process::exit(1);
}

fn main() {
    // Start anti-debug timer (detects single-stepping)
    let timer = security::anti_debug_timer_start();

    let args: Vec<String> = env::args().collect();
    let me = args
        .first()
        .cloned()
        .or_else(|| env::var("_").ok())
        .unwrap_or_else(|| {
            eprintln!("E: neither argv[0] nor $_ works.");
            process::exit(1);
        });

    // Read payload from own executable
    let exe_path = env::current_exe().unwrap_or_else(|e| {
        die(&me, &format!("cannot find own executable: {}", e));
    });

    let file = File::open(&exe_path).unwrap_or_else(|e| {
        die(&me, &format!("{}", e));
    });
    let mut reader = BufReader::new(file);

    let payload = Payload::read_from_exe(&mut reader).unwrap_or_else(|e| {
        die(&me, &format!("invalid payload: {}", e));
    });
    drop(reader);

    // Anti-debug: check if untraceable flag is set (FLAG_TRACEABLE == 0 means untraceable)
    if payload.flags & FLAG_TRACEABLE == 0 {
        // Disable core dumps and verify success
        if !security::disable_core_dump() {
            let msg = obfuscated_msg(&security::xor_encode(b"cannot disable core dumps", XOR_KEY));
            die(&me, &msg);
        }

        // Prevent privilege escalation via setuid binaries
        security::set_no_new_privs();

        // Detect debugger
        if security::detect_debugger() {
            let msg = obfuscated_msg(&security::xor_encode(b"debugger detected", XOR_KEY));
            die(&me, &msg);
        }
    }

    // Verify binary integrity (SHA-256 of runner portion)
    if payload.integrity_hash != [0u8; 32] {
        match security::verify_binary_integrity(&exe_path, &payload.integrity_hash) {
            Ok(true) => {}
            Ok(false) => {
                let msg = obfuscated_msg(&security::xor_encode(
                    b"binary integrity check failed",
                    XOR_KEY,
                ));
                die(&me, &msg);
            }
            Err(_) => {
                let msg = obfuscated_msg(&security::xor_encode(
                    b"cannot verify binary integrity",
                    XOR_KEY,
                ));
                die(&me, &msg);
            }
        }
    }

    // Password protection (Argon2id)
    if payload.ext_flags & FLAG_EXT_PASSWORD != 0 {
        let password = security::read_password("Password: ").unwrap_or_else(|e| {
            die(&me, &format!("cannot read password: {}", e));
        });
        let hash = security::hash_password(password.as_bytes(), &payload.password_salt);
        if hash != payload.password_hash {
            let msg = obfuscated_msg(&security::xor_encode(b"wrong password", XOR_KEY));
            die(&me, &msg);
        }
    }

    // Host binding check: verify machine identity matches build-time identity
    // Machine ID is stored in password_salt when password is not used
    if payload.ext_flags & FLAG_EXT_BIND_HOST != 0 && payload.ext_flags & FLAG_EXT_PASSWORD == 0 {
        let current_identity = security::get_machine_identity();
        if current_identity != payload.password_salt {
            let msg = obfuscated_msg(&security::xor_encode(b"host binding mismatch", XOR_KEY));
            die(&me, &msg);
        }
    }

    // Max runs check (with file locking)
    if payload.max_runs > 0 {
        check_max_runs(&me, &exe_path, payload.max_runs);
    }

    // Drop network access if requested (Linux network namespace isolation)
    if payload.ext_flags & FLAG_EXT_NO_NETWORK != 0 && !security::drop_network() {
        // Fatal on Linux (where unshare should work), non-fatal on other platforms
        #[cfg(target_os = "linux")]
        {
            let msg = obfuscated_msg(&security::xor_encode(
                b"cannot drop network access",
                XOR_KEY,
            ));
            die(&me, &msg);
        }
    }

    // setuid(0) if requested (Unix only)
    #[cfg(unix)]
    if payload.flags & FLAG_SETUID != 0 {
        unsafe {
            libc::setuid(0);
        }
    }

    // Clone encrypted arrays
    let pswd = payload.arrays[payload::IDX_PSWD].clone();
    let mut msg1 = payload.arrays[payload::IDX_MSG1].clone();
    let mut date = payload.arrays[payload::IDX_DATE].clone();
    let mut shll = payload.arrays[payload::IDX_SHLL].clone();
    let mut inlo = payload.arrays[payload::IDX_INLO].clone();
    let mut xecc = payload.arrays[payload::IDX_XECC].clone();
    let mut lsto = payload.arrays[payload::IDX_LSTO].clone();
    let mut tst1 = payload.arrays[payload::IDX_TST1].clone();
    let mut chk1 = payload.arrays[payload::IDX_CHK1].clone();
    let mut msg2 = payload.arrays[payload::IDX_MSG2].clone();
    let mut rlax = payload.arrays[payload::IDX_RLAX].clone();
    let mut opts = payload.arrays[payload::IDX_OPTS].clone();
    let mut text = payload.arrays[payload::IDX_TEXT].clone();
    let mut tst2 = payload.arrays[payload::IDX_TST2].clone();
    let mut chk2 = payload.arrays[payload::IDX_CHK2].clone();

    // Lock sensitive memory pages to prevent swapping to disk
    security::mlock_buffer(&text);
    security::mark_dontdump(&text);

    // Extract AEAD key if AES or ChaCha mode is enabled (first 32 bytes of pswd)
    let has_aead = payload.ext_flags & (FLAG_EXT_AES | FLAG_EXT_CHACHA) != 0;
    let mut aes_key = [0u8; 32];
    let rc4_pswd = if has_aead {
        if pswd.len() < 32 {
            die(&me, "invalid AEAD payload");
        }
        aes_key.copy_from_slice(&pswd[..32]);
        security::mlock_buffer(&aes_key);
        pswd[32..].to_vec()
    } else {
        pswd
    };

    // Decrypt — same sequence as codegen encryption and C runtime's xsh()
    let mut rc4 = Rc4::new();
    rc4.reset();
    rc4.key(&rc4_pswd);

    rc4.arc4(&mut msg1);
    rc4.arc4(&mut date);

    // Check expiry
    let date_str = bytes_to_str(&date);
    if !date_str.is_empty() {
        if let Ok(expiry) = date_str.parse::<i64>() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if expiry < now {
                let msg = bytes_to_str(&msg1);
                eprintln!("{}", msg);
                process::exit(1);
            }
        }
    }

    rc4.arc4(&mut shll);
    rc4.arc4(&mut inlo);
    rc4.arc4(&mut xecc);
    rc4.arc4(&mut lsto);
    rc4.arc4(&mut tst1);

    // Integrity check 1: key with decrypted tst1, decrypt chk1, compare
    rc4.key(&tst1);
    rc4.arc4(&mut chk1);
    if chk1.len() != tst1.len() || chk1 != tst1 {
        let msg = bytes_to_str(&tst1);
        die(&me, &msg);
    }

    rc4.arc4(&mut msg2);

    // Decrypt relax flag, then conditionally key_with_file
    rc4.arc4(&mut rlax);
    #[cfg(unix)]
    if !rlax.is_empty() && rlax[0] == 0 {
        let shll_str = bytes_to_str(&shll);
        if rc4.key_with_file(&shll_str).is_err() {
            die(&me, &shll_str);
        }
    }

    rc4.arc4(&mut opts);
    rc4.arc4(&mut text);
    rc4.arc4(&mut tst2);

    // Integrity check 2
    rc4.key(&tst2);
    rc4.arc4(&mut chk2);
    if chk2.len() != tst2.len() || chk2 != tst2 {
        let msg = bytes_to_str(&tst2);
        die(&me, &msg);
    }

    // Timer-based anti-debug check: if decryption took too long, likely being debugged
    if payload.flags & FLAG_TRACEABLE == 0 && security::anti_debug_timer_check(timer, 30_000) {
        die(&me, "timeout");
    }

    // Zero out integrity check buffers
    security::secure_zero(&mut tst1);
    security::secure_zero(&mut chk1);
    security::secure_zero(&mut tst2);
    security::secure_zero(&mut chk2);
    security::secure_zero(&mut msg2);

    // Reverse pre-processing: RC4 decrypted → AEAD decrypt → decompress
    let has_preprocessing =
        payload.ext_flags & (FLAG_EXT_AES | FLAG_EXT_CHACHA | FLAG_EXT_COMPRESSED) != 0;

    if has_preprocessing && text.last() == Some(&0) {
        text.pop();
    }

    // Step 1: AEAD decryption (AES-256-GCM or ChaCha20-Poly1305)
    if payload.ext_flags & FLAG_EXT_AES != 0 {
        let decrypted =
            rshc::aes::aes_decrypt(&text, &aes_key, &payload.aes_nonce).unwrap_or_else(|e| {
                die(&me, &format!("AES decryption failed: {}", e));
            });
        security::secure_zero(&mut text);
        text = decrypted;
    } else if payload.ext_flags & FLAG_EXT_CHACHA != 0 {
        let decrypted = rshc::chacha::chacha_decrypt(&text, &aes_key, &payload.aes_nonce)
            .unwrap_or_else(|e| {
                die(&me, &format!("ChaCha20 decryption failed: {}", e));
            });
        security::secure_zero(&mut text);
        text = decrypted;
    }

    // Step 2: Decompress
    if payload.ext_flags & FLAG_EXT_COMPRESSED != 0 {
        use flate2::read::DeflateDecoder;
        use std::io::Read;

        let mut decoder = DeflateDecoder::new(&text[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap_or_else(|e| {
            die(&me, &format!("decompression failed: {}", e));
        });
        security::secure_zero(&mut text);
        text = decompressed;
    }

    // Zero out AEAD key and unlock memory
    security::munlock_buffer(&aes_key);
    aes_key.zeroize();

    // Debug exec mode
    let debug_exec = payload.flags & FLAG_DEBUGEXEC != 0;

    // Convert decrypted fields to strings
    let shll_str = bytes_to_str(&shll);
    let inlo_str = bytes_to_str(&inlo);
    let opts_str = bytes_to_str(&opts);
    let lsto_str = bytes_to_str(&lsto);
    let text_str = if has_preprocessing {
        String::from_utf8_lossy(&text).to_string()
    } else {
        bytes_to_str(&text)
    };

    // Zero out sensitive buffers
    security::secure_zero(&mut shll);
    security::secure_zero(&mut inlo);
    security::secure_zero(&mut opts);
    security::secure_zero(&mut lsto);
    security::secure_zero(&mut text);
    security::secure_zero(&mut msg1);
    security::secure_zero(&mut date);
    security::secure_zero(&mut xecc);
    security::secure_zero(&mut rlax);

    if payload.ext_flags & FLAG_EXT_STDIN_MODE != 0 {
        exec_stdin_mode(
            &me, &args, &shll_str, &opts_str, &lsto_str, &text_str, debug_exec,
        );
    } else {
        exec_arg_mode(
            &me, &args, &shll_str, &inlo_str, &opts_str, &lsto_str, &text_str, debug_exec,
        );
    }
}

/// Execute in classic arg mode: pass script via -c argument.
#[allow(clippy::too_many_arguments)]
fn exec_arg_mode(
    me: &str,
    args: &[String],
    shll_str: &str,
    inlo_str: &str,
    opts_str: &str,
    lsto_str: &str,
    text_str: &str,
    debug_exec: bool,
) -> ! {
    // Prepend hide_z (4096) spaces to hide script in process listing
    let hide_z = 1usize << 12;
    let mut scrpt = " ".repeat(hide_z);
    scrpt.push_str(text_str);

    let mut cmd = std::process::Command::new(shll_str);

    // On Unix, replace this process with execvp
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.arg0(me);
    }

    if !opts_str.is_empty() {
        cmd.arg(opts_str);
    }
    if !inlo_str.is_empty() {
        cmd.arg(inlo_str);
    }
    cmd.arg(&scrpt);
    if !lsto_str.is_empty() {
        cmd.arg(lsto_str);
    }
    for arg in args {
        cmd.arg(arg);
    }

    if debug_exec {
        eprintln!("[rshc-runner] exec: {} {}", shll_str, inlo_str);
        eprintln!("[rshc-runner] script length: {}", text_str.len());
    }

    // Unix: replace process with exec (never returns on success)
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        eprintln!("{}: {}: {}", me, shll_str, err);
        process::exit(1);
    }

    // Windows: spawn child process and wait
    #[cfg(windows)]
    {
        let status = cmd.status().unwrap_or_else(|e| {
            eprintln!("{}: {}: {}", me, shll_str, e);
            process::exit(1);
        });
        process::exit(status.code().unwrap_or(1));
    }
}

/// Execute in stdin mode: pipe script via stdin to hide from /proc/*/cmdline.
fn exec_stdin_mode(
    me: &str,
    args: &[String],
    shll_str: &str,
    opts_str: &str,
    lsto_str: &str,
    text_str: &str,
    debug_exec: bool,
) -> ! {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(shll_str);

    if !opts_str.is_empty() {
        cmd.arg(opts_str);
    }
    if !lsto_str.is_empty() {
        cmd.arg(lsto_str);
    }
    for arg in args.iter().skip(1) {
        cmd.arg(arg);
    }

    cmd.stdin(Stdio::piped());

    if debug_exec {
        eprintln!("[rshc-runner] exec (stdin mode): {}", shll_str);
        eprintln!("[rshc-runner] script length: {}", text_str.len());
    }

    let mut child = cmd.spawn().unwrap_or_else(|e| {
        die(me, &format!("{}: {}", shll_str, e));
    });

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text_str.as_bytes()).unwrap_or_else(|e| {
            die(me, &format!("cannot write to shell stdin: {}", e));
        });
    }

    let status = child.wait().unwrap_or_else(|e| {
        die(me, &format!("cannot wait for shell: {}", e));
    });

    process::exit(status.code().unwrap_or(1));
}

/// Check and update the max-runs counter with file locking to prevent TOCTOU races.
fn check_max_runs(me: &str, exe_path: &std::path::Path, max_runs: u32) {
    use std::io::{Read, Seek, SeekFrom, Write};

    let counter_path = format!("{}.runs", exe_path.display());

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&counter_path)
        .unwrap_or_else(|e| {
            die(
                me,
                &format!("cannot open counter file {}: {}", counter_path, e),
            );
        });

    // Acquire exclusive lock
    lock_file_exclusive(&file, me);

    // Read current count
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap_or_default();
    let current: u32 = contents.trim().parse().unwrap_or(0);

    if current >= max_runs {
        let msg = obfuscated_msg(&security::xor_encode(
            b"maximum executions reached",
            XOR_KEY,
        ));
        die(me, &msg);
    }

    // Write incremented count atomically (under lock)
    file.seek(SeekFrom::Start(0)).unwrap_or_else(|e| {
        die(me, &format!("counter seek failed: {}", e));
    });
    file.set_len(0).unwrap_or_else(|e| {
        die(me, &format!("counter truncate failed: {}", e));
    });
    write!(file, "{}", current + 1).unwrap_or_else(|e| {
        die(me, &format!("counter write failed: {}", e));
    });
    // Lock released on drop
}

/// Platform-specific exclusive file lock.
#[cfg(unix)]
fn lock_file_exclusive(file: &std::fs::File, me: &str) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        if libc::flock(file.as_raw_fd(), libc::LOCK_EX) != 0 {
            die(me, "cannot lock counter file");
        }
    }
}

/// Fallback file lock for non-Unix platforms (best-effort).
#[cfg(not(unix))]
fn lock_file_exclusive(_file: &std::fs::File, _me: &str) {
    // On Windows/other platforms, file locking is best-effort.
    // The counter still works but is not race-condition-proof.
}

/// Convert null-terminated byte slice to string, stripping the trailing \0.
fn bytes_to_str(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    s.trim_end_matches('\0').to_string()
}
