//! rshc-runner: Native Rust runtime for rshc-compiled scripts.
//!
//! This binary is used as a stub: rshc copies it and appends an encrypted
//! payload to the end. At runtime, the runner reads the payload from its
//! own executable, decrypts the script, and exec's the target shell.
//!
//! Security features:
//! - Multi-layer anti-debug (ptrace, SIGTRAP, Frida, parent process, env injection, TracerPid, RDTSC timing)
//! - Seccomp-BPF syscall filtering (blocks ptrace, process_vm_readv/writev)
//! - Constant-time comparisons for all secret data (prevents timing attacks)
//! - mmap-backed protected memory with PROT_NONE/PROT_READ toggling
//! - Memory zeroing for all sensitive data (zeroize)
//! - Binary self-integrity check (SHA-256)
//! - AES-256-GCM / ChaCha20-Poly1305 encryption (on top of RC4)
//! - Password protection (Argon2id hash verification)
//! - Script compression (deflate)
//! - Max execution count (with file locking)
//! - VM/hypervisor detection (CPUID / DMI)
//! - Core dump prevention (RLIMIT_CORE + PR_SET_DUMPABLE)
//! - Cross-platform support (Unix + Windows)

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use rshc::payload::{
    self, Payload, FLAG_DEBUGEXEC, FLAG_EXT_AES, FLAG_EXT_ANTI_VM, FLAG_EXT_BIND_HOST,
    FLAG_EXT_CHACHA, FLAG_EXT_COMPRESSED, FLAG_EXT_NO_NETWORK, FLAG_EXT_PASSWORD,
    FLAG_EXT_STDIN_MODE, FLAG_SETUID, FLAG_TRACEABLE,
};
use rshc::rc4::Rc4;
use rshc::security;

fn die(me: &str, msg: &str) -> ! {
    eprintln!("{}: {}", me, msg);
    process::exit(1);
}

fn main() {
    // Start anti-debug timers (wall-clock + CPU cycle counter)
    let timer = security::anti_debug_timer_start();
    let rdtsc_start = security::rdtsc_timestamp();

    let args: Vec<String> = env::args().collect();
    let me = args
        .first()
        .cloned()
        .or_else(|| env::var("_").ok())
        .unwrap_or_else(|| {
            eprintln!("{}", obfstr::obfstr!("E: neither argv[0] nor $_ works."));
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
            die(&me, obfstr::obfstr!("cannot disable core dumps"));
        }

        // Prevent privilege escalation via setuid binaries
        security::set_no_new_privs();

        // Multi-layer debugger detection:
        // 1. ptrace (PTRACE_TRACEME / PT_DENY_ATTACH)
        // 2. Environment injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES, etc.)
        // 3. TracerPid in /proc/self/status (Linux)
        // 4. SIGTRAP handler test (signal-based, catches GDB/LLDB)
        // 5. Frida detection (/proc/self/maps + thread names)
        // 6. Parent process name check (detects gdb, strace, etc.)
        if security::detect_debugger() {
            die(&me, obfstr::obfstr!("debugger detected"));
        }

        // RDTSC timing check: single-stepping adds thousands of cycles
        // Check after anti-debug (which involves syscalls) but threshold is generous
        if security::rdtsc_check_elapsed(rdtsc_start, 500_000_000) {
            die(&me, obfstr::obfstr!("timing anomaly"));
        }

        // Deny write-execute memory (Linux 6.3+): prevents code injection
        security::deny_write_execute();

        // Install seccomp-BPF filter AFTER anti-debug checks
        // Blocks: ptrace, process_vm_readv, process_vm_writev
        // This prevents debugger attachment after our checks pass
        security::install_seccomp_filter();
    }

    // Anti-VM detection (opt-in via --anti-vm flag)
    if payload.ext_flags & FLAG_EXT_ANTI_VM != 0 && security::detect_vm() {
        die(&me, obfstr::obfstr!("unsupported environment"));
    }

    // Verify binary integrity (SHA-256 of runner portion)
    if payload.integrity_hash != [0u8; 32] {
        match security::verify_binary_integrity(&exe_path, &payload.integrity_hash) {
            Ok(true) => {}
            Ok(false) => {
                die(&me, obfstr::obfstr!("binary integrity check failed"));
            }
            Err(_) => {
                die(&me, obfstr::obfstr!("cannot verify binary integrity"));
            }
        }
    }

    // Password protection: derive the AEAD key from the password (Argon2id).
    // The domain-separated constant-time pre-check gives a clean "wrong
    // password" error, but the AEAD auth tag is the true gate — a wrong
    // password derives the wrong key, so decryption fails below regardless.
    let has_password = payload.ext_flags & FLAG_EXT_PASSWORD != 0;
    let mut password_aead_key = [0u8; 32];
    if has_password {
        let mut password = security::read_password("Password: ").unwrap_or_else(|e| {
            die(&me, &format!("cannot read password: {}", e));
        });
        let mut derived = security::derive_key_argon2(password.as_bytes(), &payload.password_salt);
        password.zeroize();
        let verify = security::password_verify_hash(&derived);
        if !security::constant_time_eq(&verify, &payload.password_hash) {
            die(&me, obfstr::obfstr!("wrong password"));
        }
        password_aead_key.copy_from_slice(&derived);
        derived.zeroize();
        security::mlock_buffer(&password_aead_key);
    }

    // Host binding check — constant-time comparison
    if payload.ext_flags & FLAG_EXT_BIND_HOST != 0 && payload.ext_flags & FLAG_EXT_PASSWORD == 0 {
        let current_identity = security::get_machine_identity();
        if !security::constant_time_eq(&current_identity, &payload.password_salt) {
            die(&me, obfstr::obfstr!("host binding mismatch"));
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
        die(&me, obfstr::obfstr!("cannot drop network access"));
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

    // AEAD key resolution:
    // - password mode: the key was derived from the password above; pswd is the
    //   full RC4 key (nothing was prepended at build time).
    // - aes/chacha WITHOUT password: the random key is the first 32 bytes of pswd.
    let has_aead = payload.ext_flags & (FLAG_EXT_AES | FLAG_EXT_CHACHA) != 0;
    let mut aes_key = [0u8; 32];
    let rc4_pswd = if has_password {
        aes_key.copy_from_slice(&password_aead_key);
        security::mlock_buffer(&aes_key);
        security::munlock_buffer(&password_aead_key);
        password_aead_key.zeroize();
        pswd
    } else if has_aead {
        if pswd.len() < 32 {
            die(&me, obfstr::obfstr!("invalid AEAD payload"));
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
                .unwrap_or(Duration::ZERO)
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

    // Integrity check 1 — constant-time comparison
    rc4.key(&tst1);
    rc4.arc4(&mut chk1);
    if !security::constant_time_eq(&chk1, &tst1) {
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

    // Integrity check 2 — constant-time comparison
    rc4.key(&tst2);
    rc4.arc4(&mut chk2);
    if !security::constant_time_eq(&chk2, &tst2) {
        let msg = bytes_to_str(&tst2);
        die(&me, &msg);
    }

    // Timer-based anti-debug check: if decryption took too long, likely being debugged
    if payload.flags & FLAG_TRACEABLE == 0 && security::anti_debug_timer_check(timer, 30_000) {
        die(&me, obfstr::obfstr!("timeout"));
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
                die(
                    &me,
                    &format!("{}: {}", obfstr::obfstr!("AES decryption failed"), e),
                );
            });
        security::secure_zero(&mut text);
        text = decrypted;
    } else if payload.ext_flags & FLAG_EXT_CHACHA != 0 {
        let decrypted = rshc::chacha::chacha_decrypt(&text, &aes_key, &payload.aes_nonce)
            .unwrap_or_else(|e| {
                die(
                    &me,
                    &format!("{}: {}", obfstr::obfstr!("ChaCha20 decryption failed"), e),
                );
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
            die(
                &me,
                &format!("{}: {}", obfstr::obfstr!("decompression failed"), e),
            );
        });
        security::secure_zero(&mut text);
        text = decompressed;
    }

    // Zero out AEAD key and unlock memory
    security::munlock_buffer(&aes_key);
    aes_key.zeroize();

    // Debug exec mode
    let debug_exec = payload.flags & FLAG_DEBUGEXEC != 0;

    // Convert decrypted text to a string
    let text_bytes = if has_preprocessing {
        text.clone()
    } else {
        let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
        text[..end].to_vec()
    };

    // Move decrypted text into a ProtectedBuffer (mmap-backed, page-aligned, mlocked)
    // This is the ONLY copy of the plaintext — original vec is zeroed
    let protected_text = security::ProtectedBuffer::new(&text_bytes);

    // Zero the heap copies — only the ProtectedBuffer holds the plaintext
    security::secure_zero(&mut text);
    let mut text_bytes = text_bytes;
    security::secure_zero(&mut text_bytes);
    drop(text_bytes);

    // Protect the buffer (PROT_NONE) — memory dumps will see inaccessible pages
    if let Some(ref pt) = protected_text {
        pt.protect();
    }

    // Convert other decrypted fields to strings and zero originals
    let shll_str = bytes_to_str(&shll);
    let inlo_str = bytes_to_str(&inlo);
    let opts_str = bytes_to_str(&opts);
    let lsto_str = bytes_to_str(&lsto);

    security::secure_zero(&mut shll);
    security::secure_zero(&mut inlo);
    security::secure_zero(&mut opts);
    security::secure_zero(&mut lsto);
    security::secure_zero(&mut msg1);
    security::secure_zero(&mut date);
    security::secure_zero(&mut xecc);
    security::secure_zero(&mut rlax);

    // Unprotect text just before exec — minimize plaintext exposure window
    if let Some(ref pt) = protected_text {
        pt.unprotect_read();
    }
    // Keep the decrypted script as raw bytes — a lossy UTF-8 conversion would
    // corrupt scripts containing non-UTF-8 bytes. shll/opts/etc. stay strings.
    let empty: &[u8] = &[];
    let script_bytes: &[u8] = protected_text
        .as_ref()
        .map(|p| p.as_slice())
        .unwrap_or(empty);

    if payload.ext_flags & FLAG_EXT_STDIN_MODE != 0 {
        exec_stdin_mode(
            &me,
            &args,
            &shll_str,
            &opts_str,
            &lsto_str,
            script_bytes,
            debug_exec,
        );
    } else {
        exec_arg_mode(
            &me,
            &args,
            &shll_str,
            &inlo_str,
            &opts_str,
            &lsto_str,
            script_bytes,
            debug_exec,
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
    text_bytes: &[u8],
    debug_exec: bool,
) -> ! {
    // Prepend hide_z (4096) spaces to hide script in process listing.
    // Build the argument from raw bytes so non-UTF-8 script bytes reach execvp
    // unchanged (a String conversion would be lossy).
    let hide_z = 1usize << 12;

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

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut scrpt = vec![b' '; hide_z];
        scrpt.extend_from_slice(text_bytes);
        cmd.arg(std::ffi::OsStr::from_bytes(&scrpt));
    }
    #[cfg(windows)]
    {
        let mut scrpt = " ".repeat(hide_z);
        scrpt.push_str(&String::from_utf8_lossy(text_bytes));
        cmd.arg(&scrpt);
    }

    if !lsto_str.is_empty() {
        cmd.arg(lsto_str);
    }
    for arg in args {
        cmd.arg(arg);
    }

    if debug_exec {
        eprintln!(
            "{} {} {}",
            obfstr::obfstr!("[rshc-runner] exec:"),
            shll_str,
            inlo_str
        );
        eprintln!(
            "{} {}",
            obfstr::obfstr!("[rshc-runner] script length:"),
            text_bytes.len()
        );
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
    text_bytes: &[u8],
    debug_exec: bool,
) -> ! {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(shll_str);

    if !opts_str.is_empty() {
        cmd.arg(opts_str);
    }
    // -s tells the shell to read from stdin; remaining args become $1, $2, ...
    cmd.arg("-s");
    if !lsto_str.is_empty() {
        cmd.arg(lsto_str);
    }
    for arg in args.iter().skip(1) {
        cmd.arg(arg);
    }

    cmd.stdin(Stdio::piped());

    if debug_exec {
        eprintln!(
            "{} {}",
            obfstr::obfstr!("[rshc-runner] exec (stdin mode):"),
            shll_str
        );
        eprintln!(
            "{} {}",
            obfstr::obfstr!("[rshc-runner] script length:"),
            text_bytes.len()
        );
    }

    let mut child = cmd.spawn().unwrap_or_else(|e| {
        die(me, &format!("{}: {}", shll_str, e));
    });

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text_bytes).unwrap_or_else(|e| {
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
                &format!(
                    "{} {}: {}",
                    obfstr::obfstr!("cannot open counter file"),
                    counter_path,
                    e
                ),
            );
        });

    // Acquire exclusive lock
    lock_file_exclusive(&file, me);

    // Read current count
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap_or_default();
    let current: u32 = contents.trim().parse().unwrap_or(0);

    if current >= max_runs {
        die(me, obfstr::obfstr!("maximum executions reached"));
    }

    // Write incremented count atomically (under lock)
    file.seek(SeekFrom::Start(0)).unwrap_or_else(|e| {
        die(
            me,
            &format!("{}: {}", obfstr::obfstr!("counter seek failed"), e),
        );
    });
    file.set_len(0).unwrap_or_else(|e| {
        die(
            me,
            &format!("{}: {}", obfstr::obfstr!("counter truncate failed"), e),
        );
    });
    write!(file, "{}", current + 1).unwrap_or_else(|e| {
        die(
            me,
            &format!("{}: {}", obfstr::obfstr!("counter write failed"), e),
        );
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
