//! Security utilities for the rshc native runner.
//! Inspired by chenyukang/rshc (https://github.com/chenyukang/rshc).

use zeroize::Zeroize;

/// XOR-encode/decode a byte slice with a key. Used to obfuscate strings in the binary.
pub fn xor_encode(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

/// XOR-decode a byte slice (same operation as encode since XOR is symmetric).
pub fn xor_decode(data: &[u8], key: u8) -> Vec<u8> {
    xor_encode(data, key)
}

/// Securely zero a byte buffer using volatile writes.
pub fn secure_zero(buf: &mut [u8]) {
    buf.zeroize();
}

/// Securely zero a Vec<u8> and deallocate.
pub fn secure_zero_vec(buf: &mut Vec<u8>) {
    buf.zeroize();
}

/// Check for common anti-debug indicators.
/// Returns true if a debugger is likely attached.
pub fn detect_debugger() -> bool {
    if detect_ptrace() {
        return true;
    }
    if detect_env_injection() {
        return true;
    }
    #[cfg(target_os = "linux")]
    if detect_tracer_linux() {
        return true;
    }
    false
}

/// Try to detect if the process is being ptraced.
fn detect_ptrace() -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let result = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            if result == -1 {
                return true;
            }
            libc::ptrace(libc::PTRACE_DETACH, 0, 0, 0);
        }
    }

    #[cfg(target_os = "macos")]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        unsafe {
            let result = libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
            if result == -1 {
                return true;
            }
        }
    }

    false
}

/// Detect environment variable injection attacks.
/// Checks for LD_PRELOAD, LD_AUDIT, DYLD_INSERT_LIBRARIES, and other dangerous vars.
fn detect_env_injection() -> bool {
    const DANGEROUS_VARS: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "GCONV_PATH",
        "LSAN_OPTIONS",
        "ASAN_OPTIONS",
        "UBSAN_OPTIONS",
        #[cfg(target_os = "macos")]
        "DYLD_INSERT_LIBRARIES",
        #[cfg(target_os = "macos")]
        "DYLD_LIBRARY_PATH",
        #[cfg(target_os = "macos")]
        "DYLD_FRAMEWORK_PATH",
    ];
    for var in DANGEROUS_VARS {
        if std::env::var_os(var).is_some() {
            return true;
        }
    }
    false
}

/// Linux-specific: check /proc/self/status for TracerPid.
#[cfg(target_os = "linux")]
fn detect_tracer_linux() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("TracerPid:") {
                let pid = value.trim();
                if pid != "0" {
                    return true;
                }
            }
        }
    }
    false
}

/// Timer-based anti-debug: returns a checkpoint that can be verified later.
/// If too much time passes between checkpoints, single-stepping is suspected.
pub fn anti_debug_timer_start() -> std::time::Instant {
    std::time::Instant::now()
}

/// Check if too much time has elapsed since the timer started.
/// Returns true if the elapsed time exceeds the threshold (likely being debugged).
pub fn anti_debug_timer_check(start: std::time::Instant, max_ms: u64) -> bool {
    start.elapsed().as_millis() > max_ms as u128
}

/// Disable core dumps for the current process.
/// Returns false if the operation failed (caller should handle).
pub fn disable_core_dump() -> bool {
    let mut success = true;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unsafe {
        let rlimit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlimit) != 0 {
            success = false;
        }
    }

    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            success = false;
        }
    }

    success
}

/// Compute SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Hash a password with a salt using Argon2id (memory-hard, GPU-resistant).
/// Output is 32 bytes suitable for storage or key derivation.
pub fn hash_password(password: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Argon2id with moderate parameters (suitable for CLI tool):
    // m=19456 KiB (~19 MB), t=2 iterations, p=1 parallelism
    let params = Params::new(19456, 2, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut hash = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut hash)
        .expect("argon2 hash failed");
    hash
}

/// Read a password from the terminal without echoing.
pub fn read_password(prompt: &str) -> std::io::Result<String> {
    use std::io::Write;
    eprint!("{}", prompt);
    std::io::stderr().flush()?;

    #[cfg(unix)]
    {
        use std::io::BufRead;
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, &mut termios);
            let orig = termios;
            termios.c_lflag &= !libc::ECHO;
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios);

            let mut password = String::new();
            let result = std::io::stdin().lock().read_line(&mut password);

            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &orig);
            eprintln!();

            result?;
            Ok(password.trim_end().to_string())
        }
    }

    #[cfg(not(unix))]
    {
        use std::io::BufRead;
        let mut password = String::new();
        std::io::stdin().lock().read_line(&mut password)?;
        Ok(password.trim_end().to_string())
    }
}

/// Verify the integrity of a binary by checking its SHA-256 hash.
/// The binary content to hash is everything up to the payload start.
pub fn verify_binary_integrity(
    exe_path: &std::path::Path,
    expected_hash: &[u8; 32],
) -> Result<bool, std::io::Error> {
    use std::io::{Read, Seek, SeekFrom};

    if expected_hash == &[0u8; 32] {
        return Ok(true);
    }

    let mut file = std::fs::File::open(exe_path)?;

    file.seek(SeekFrom::End(-8))?;
    let mut size_buf = [0u8; 8];
    file.read_exact(&mut size_buf)?;
    let payload_size = u64::from_le_bytes(size_buf);

    let total_size = file.seek(SeekFrom::End(0))?;
    let runner_size = total_size - payload_size;

    file.seek(SeekFrom::Start(0))?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    let mut remaining = runner_size;
    let mut buf = vec![0u8; 8192];
    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        file.read_exact(&mut buf[..to_read])?;
        hasher.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }

    let actual_hash = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&actual_hash);

    Ok(hash == *expected_hash)
}

/// Compute the SHA-256 hash of a file.
pub fn hash_file(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use sha2::Digest;
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Verify that a path is not a symlink (prevent binary substitution attacks).
pub fn verify_not_symlink(path: &std::path::Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat {}: {}", path.display(), e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symlink (possible attack)", path.display()));
    }
    Ok(())
}

/// Lock memory pages to prevent swapping sensitive data to disk.
/// Call on buffers containing keys, decrypted script, etc.
#[cfg(unix)]
pub fn mlock_buffer(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0 }
}

#[cfg(not(unix))]
pub fn mlock_buffer(_buf: &[u8]) -> bool {
    true // no-op on non-Unix
}

/// Unlock previously locked memory pages.
#[cfg(unix)]
pub fn munlock_buffer(buf: &[u8]) {
    if !buf.is_empty() {
        unsafe {
            libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }
}

#[cfg(not(unix))]
pub fn munlock_buffer(_buf: &[u8]) {}

/// Mark memory as excluded from core dumps (Linux MADV_DONTDUMP).
#[cfg(target_os = "linux")]
pub fn mark_dontdump(buf: &[u8]) {
    if !buf.is_empty() {
        unsafe {
            libc::madvise(
                buf.as_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MADV_DONTDUMP,
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn mark_dontdump(_buf: &[u8]) {}

/// Drop network access by entering a new network namespace (Linux only).
/// After this call, the process has no network interfaces.
#[cfg(target_os = "linux")]
pub fn drop_network() -> bool {
    // CLONE_NEWNET = 0x40000000
    const CLONE_NEWNET: libc::c_int = 0x40000000;
    unsafe { libc::unshare(CLONE_NEWNET) == 0 }
}

#[cfg(not(target_os = "linux"))]
pub fn drop_network() -> bool {
    false // not supported on this platform
}

/// Prevent privilege escalation via setuid/setgid binaries.
/// Sets PR_SET_NO_NEW_PRIVS so that exec'd processes cannot gain new privileges.
/// This is a prerequisite for seccomp-BPF but does NOT install a BPF filter.
#[cfg(target_os = "linux")]
pub fn set_no_new_privs() -> bool {
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 }
}

#[cfg(not(target_os = "linux"))]
pub fn set_no_new_privs() -> bool {
    true // no-op on non-Linux
}

/// Get a stable machine identity hash for host binding.
/// Combines hostname + machine-id (Linux) or hardware UUID (macOS).
pub fn get_machine_identity() -> [u8; 32] {
    let mut identity = Vec::new();

    // Hostname
    #[cfg(unix)]
    {
        let mut hostname_buf = [0u8; 256];
        unsafe {
            if libc::gethostname(hostname_buf.as_mut_ptr() as *mut libc::c_char, 256) == 0 {
                let len = hostname_buf.iter().position(|&b| b == 0).unwrap_or(256);
                identity.extend_from_slice(&hostname_buf[..len]);
            }
        }
    }

    // Machine ID (Linux)
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            identity.extend_from_slice(id.trim().as_bytes());
        } else if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            identity.extend_from_slice(id.trim().as_bytes());
        }
    }

    // Hardware UUID (macOS)
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        identity.extend_from_slice(uuid.as_bytes());
                    }
                }
            }
        }
    }

    // Windows: use ComputerName
    #[cfg(windows)]
    {
        if let Ok(name) = std::env::var("COMPUTERNAME") {
            identity.extend_from_slice(name.as_bytes());
        }
    }

    // If we couldn't get any identity, use a fallback
    if identity.is_empty() {
        identity.extend_from_slice(b"unknown-host");
    }

    sha256(&identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_encode_decode_roundtrip() {
        let data = b"Hello, World!";
        let key = 0x42;
        let encoded = xor_encode(data, key);
        assert_ne!(&encoded[..], &data[..]);
        let decoded = xor_decode(&encoded, key);
        assert_eq!(&decoded[..], &data[..]);
    }

    #[test]
    fn test_xor_encode_empty() {
        let encoded = xor_encode(b"", 0x42);
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_xor_encode_zero_key() {
        let data = b"test";
        let encoded = xor_encode(data, 0x00);
        assert_eq!(&encoded[..], &data[..]);
    }

    #[test]
    fn test_secure_zero() {
        let mut buf = vec![0x42u8; 256];
        secure_zero(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_zero_vec() {
        let mut buf = vec![0x42u8; 256];
        secure_zero_vec(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_sha256_known_value() {
        let hash = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_deterministic() {
        let hash1 = sha256(b"test data");
        let hash2 = sha256(b"test data");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_different_input() {
        let hash1 = sha256(b"data1");
        let hash2 = sha256(b"data2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_argon2_deterministic() {
        let salt = [0x11u8; 32];
        let hash1 = hash_password(b"password", &salt);
        let hash2 = hash_password(b"password", &salt);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_argon2_different_salts() {
        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];
        let hash1 = hash_password(b"password", &salt1);
        let hash2 = hash_password(b"password", &salt2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_argon2_different_passwords() {
        let salt = [0x11u8; 32];
        let hash1 = hash_password(b"password1", &salt);
        let hash2 = hash_password(b"password2", &salt);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_argon2_not_trivial() {
        // Argon2 output should not be a simple SHA-256 hash
        let salt = [0x11u8; 32];
        let argon2_hash = hash_password(b"test", &salt);
        let sha_hash = sha256(b"test");
        assert_ne!(argon2_hash, sha_hash);
    }

    #[test]
    fn test_detect_env_injection_clean() {
        let _ = detect_env_injection();
    }

    #[test]
    fn test_hash_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"test file content").unwrap();
        tmp.flush().unwrap();

        let hash1 = hash_file(tmp.path()).unwrap();
        let hash2 = hash_file(tmp.path()).unwrap();
        assert_eq!(hash1, hash2);

        let expected = sha256(b"test file content");
        assert_eq!(hash1, expected);
    }

    #[test]
    fn test_verify_binary_integrity_zeros_skip() {
        let path = std::path::Path::new("/nonexistent");
        let hash = [0u8; 32];
        assert!(verify_binary_integrity(path, &hash).unwrap());
    }

    #[test]
    fn test_disable_core_dump_returns_result() {
        let result = disable_core_dump();
        // Should succeed in normal test environment
        assert!(result);
    }

    #[test]
    fn test_xor_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let key = 0xAB;
        let encoded = xor_encode(&data, key);
        let decoded = xor_decode(&encoded, key);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_anti_debug_timer() {
        let start = anti_debug_timer_start();
        // Should not trigger immediately (threshold 10s)
        assert!(!anti_debug_timer_check(start, 10_000));
    }

    #[test]
    fn test_verify_not_symlink_regular_file() {
        use std::io::Write;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = tmp.reopen().unwrap();
        f.write_all(b"test").unwrap();
        assert!(verify_not_symlink(tmp.path()).is_ok());
    }

    #[test]
    fn test_verify_not_symlink_detects_symlink() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        let link_path = link_dir.path().join("link");
        std::os::unix::fs::symlink(tmp.path(), &link_path).unwrap();
        assert!(verify_not_symlink(&link_path).is_err());
    }

    #[test]
    fn test_mlock_buffer() {
        let buf = vec![0x42u8; 4096];
        // mlock may fail in constrained environments (ulimit), but should not panic
        let _ = mlock_buffer(&buf);
        munlock_buffer(&buf);
    }

    #[test]
    fn test_mlock_empty_buffer() {
        assert!(mlock_buffer(&[]));
    }

    #[test]
    fn test_mark_dontdump_doesnt_crash() {
        let buf = vec![0x42u8; 4096];
        mark_dontdump(&buf);
    }

    #[test]
    fn test_get_machine_identity_deterministic() {
        let id1 = get_machine_identity();
        let id2 = get_machine_identity();
        assert_eq!(id1, id2);
        // Should not be all zeros
        assert_ne!(id1, [0u8; 32]);
    }

    #[test]
    fn test_set_no_new_privs() {
        let _ = set_no_new_privs();
    }
}
