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
/// Combines multiple detection techniques for defense-in-depth.
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
    if detect_sigtrap() {
        return true;
    }
    if detect_frida() {
        return true;
    }
    if detect_parent_debugger() {
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

// --- Advanced Security Features ---

/// Constant-time byte comparison to prevent timing side-channel attacks.
/// Uses the `subtle` crate's constant-time equality check.
/// Critical for password hash and integrity hash comparisons.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// SIGTRAP-based anti-debug detection.
/// Installs a SIGTRAP handler via sigaction(), raises SIGTRAP, and checks if the handler ran.
/// Under a debugger (GDB/LLDB), SIGTRAP is intercepted and the handler never executes.
/// Uses sigaction() instead of signal() for more reliable handler management.
#[cfg(unix)]
pub fn detect_sigtrap() -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};

    static HANDLER_RAN: AtomicBool = AtomicBool::new(false);

    extern "C" fn sigtrap_handler(_sig: libc::c_int) {
        HANDLER_RAN.store(true, Ordering::SeqCst);
    }

    unsafe {
        HANDLER_RAN.store(false, Ordering::SeqCst);

        // Use sigaction for reliable handler semantics (no SA_RESETHAND race)
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigtrap_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);

        let mut old_sa: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGTRAP, &sa, &mut old_sa) != 0 {
            return false; // Can't install handler, skip check
        }

        libc::raise(libc::SIGTRAP);

        // Restore previous handler
        libc::sigaction(libc::SIGTRAP, &old_sa, std::ptr::null_mut());

        !HANDLER_RAN.load(Ordering::SeqCst)
    }
}

#[cfg(not(unix))]
pub fn detect_sigtrap() -> bool {
    false
}

/// Detect Frida dynamic instrumentation framework (Linux).
/// Scans /proc/self/maps for Frida artifacts and checks thread names for
/// Frida-specific threads (gum-js-loop, gmain, gdbus).
#[cfg(target_os = "linux")]
pub fn detect_frida() -> bool {
    // Check /proc/self/maps for Frida memory-mapped artifacts
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let maps_lower = maps.to_lowercase();
        let artifacts = ["frida", "gadget", "memfd:jit-cache"];
        for artifact in &artifacts {
            if maps_lower.contains(artifact) {
                return true;
            }
        }
    }

    // Check thread names for Frida-specific threads
    if let Ok(entries) = std::fs::read_dir("/proc/self/task") {
        for entry in entries.flatten() {
            let comm_path = entry.path().join("comm");
            if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                let name = comm.trim();
                if name.contains("gum-js-loop") || name.contains("gmain") || name == "gdbus" {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(not(target_os = "linux"))]
pub fn detect_frida() -> bool {
    false
}

/// Check if the parent process is a known debugger or analysis tool.
/// Reads /proc/<ppid>/comm on Linux to identify the parent process name.
#[cfg(target_os = "linux")]
pub fn detect_parent_debugger() -> bool {
    let ppid = unsafe { libc::getppid() };
    let comm_path = format!("/proc/{}/comm", ppid);
    if let Ok(comm) = std::fs::read_to_string(&comm_path) {
        let name = comm.trim().to_lowercase();
        const DEBUGGERS: &[&str] = &[
            "gdb", "lldb", "strace", "ltrace", "radare2", "r2", "ida", "x64dbg", "edb",
        ];
        for dbg in DEBUGGERS {
            if name == *dbg || name.starts_with(dbg) {
                return true;
            }
        }
    }
    false
}

/// macOS: Check P_TRACED flag via sysctl to detect if a debugger is attached.
/// Uses raw bytes since kinfo_proc is not available in the libc crate.
#[cfg(target_os = "macos")]
pub fn detect_parent_debugger() -> bool {
    // On macOS, PT_DENY_ATTACH in detect_ptrace() is the primary anti-debug.
    // As supplementary check, verify the process is not being traced via sysctl.
    // The P_TRACED flag is at byte offset 32 (kp_proc.p_flag) in kinfo_proc.
    const KINFO_PROC_SIZE: usize = 648; // sizeof(struct kinfo_proc) on macOS arm64/x86_64
    const P_FLAG_OFFSET: usize = 32; // offsetof(kinfo_proc, kp_proc.p_flag)
    const P_TRACED: i32 = 0x00000800;

    unsafe {
        let pid = libc::getpid();
        let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut buf = [0u8; KINFO_PROC_SIZE];
        let mut size = KINFO_PROC_SIZE;
        let ret = libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if ret == 0 && size >= P_FLAG_OFFSET + 4 {
            let p_flag = i32::from_ne_bytes([
                buf[P_FLAG_OFFSET],
                buf[P_FLAG_OFFSET + 1],
                buf[P_FLAG_OFFSET + 2],
                buf[P_FLAG_OFFSET + 3],
            ]);
            return p_flag & P_TRACED != 0;
        }
    }
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn detect_parent_debugger() -> bool {
    false
}

/// RDTSC-based anti-debug timing check (x86_64 only).
/// Returns the current CPU timestamp counter value.
/// Debugger single-stepping adds thousands of cycles per instruction.
#[cfg(target_arch = "x86_64")]
pub fn rdtsc_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn rdtsc_timestamp() -> u64 {
    0
}

/// Check if the cycle count since `start` exceeds `max_cycles`.
/// Returns true if debugging is suspected (too many cycles elapsed).
/// A threshold of ~10_000_000 cycles is generous for normal execution
/// but catches single-stepping.
#[cfg(target_arch = "x86_64")]
pub fn rdtsc_check_elapsed(start: u64, max_cycles: u64) -> bool {
    let end = unsafe { core::arch::x86_64::_rdtsc() };
    end.wrapping_sub(start) > max_cycles
}

#[cfg(not(target_arch = "x86_64"))]
pub fn rdtsc_check_elapsed(_start: u64, _max_cycles: u64) -> bool {
    false
}

/// Install a minimal seccomp-BPF filter that blocks dangerous syscalls (Linux only).
/// Blocks: ptrace, process_vm_readv, process_vm_writev.
/// These syscalls are used by debuggers and memory inspection tools.
/// Must be called AFTER anti-debug checks that themselves use ptrace.
#[cfg(target_os = "linux")]
pub fn install_seccomp_filter() -> bool {
    // BPF instruction constants
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

    #[cfg(target_arch = "x86_64")]
    const BLOCKED: &[u32] = &[101, 310, 311]; // ptrace, process_vm_readv, process_vm_writev
    #[cfg(target_arch = "aarch64")]
    const BLOCKED: &[u32] = &[117, 270, 271]; // ptrace, process_vm_readv, process_vm_writev
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const BLOCKED: &[u32] = &[];

    if BLOCKED.is_empty() {
        return false;
    }

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    let mut filter = Vec::new();

    // Load syscall number (offset 0 in seccomp_data)
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });

    // For each blocked syscall: jump to KILL if match, else continue
    let n = BLOCKED.len();
    for (i, &nr) in BLOCKED.iter().enumerate() {
        filter.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: (n - i) as u8,
            jf: 0,
            k: nr,
        });
    }

    // ALLOW (default action for non-blocked syscalls)
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // KILL (target for blocked syscalls)
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    unsafe {
        // PR_SET_NO_NEW_PRIVS is required before installing seccomp filters
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const SockFprog as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) == 0
    }
}

#[cfg(not(target_os = "linux"))]
pub fn install_seccomp_filter() -> bool {
    false
}

/// Detect if running inside a virtual machine (x86_64 only).
/// Checks CPUID hypervisor present bit (leaf 1, ECX bit 31).
/// This bit is set by all major hypervisors (VMware, VirtualBox, KVM, Hyper-V, Xen).
#[cfg(target_arch = "x86_64")]
pub fn detect_vm() -> bool {
    unsafe {
        let result = core::arch::x86_64::__cpuid(1);
        result.ecx & (1 << 31) != 0
    }
}

/// Linux non-x86_64: check DMI/SMBIOS for VM identifiers.
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
pub fn detect_vm() -> bool {
    let dmi_paths = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
    ];
    let vm_strings = [
        "virtualbox",
        "vmware",
        "qemu",
        "kvm",
        "xen",
        "hyper-v",
        "parallels",
    ];
    for path in &dmi_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lower = content.trim().to_lowercase();
            for vm in &vm_strings {
                if lower.contains(vm) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_os = "linux", not(target_arch = "x86_64"))
)))]
pub fn detect_vm() -> bool {
    false
}

/// Deny write-execute memory mappings (Linux 6.3+).
/// Prevents creation of memory that is both writable and executable simultaneously,
/// blocking code injection attacks. Inherited across fork().
#[cfg(target_os = "linux")]
pub fn deny_write_execute() -> bool {
    const PR_SET_MDWE: libc::c_int = 65;
    const MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
    unsafe { libc::prctl(PR_SET_MDWE, MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) == 0 }
}

#[cfg(not(target_os = "linux"))]
pub fn deny_write_execute() -> bool {
    false
}

/// Try to allocate memory via memfd_secret (Linux 5.14+).
/// Returns kernel-invisible memory: not accessible to other processes,
/// not visible via /proc/pid/mem, not accessible even to root.
/// Falls back to None if the syscall is unavailable.
#[cfg(target_os = "linux")]
fn try_memfd_secret(size: usize) -> Option<*mut u8> {
    // memfd_secret syscall number is 447 on both x86_64 and aarch64
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const SYS_MEMFD_SECRET: libc::c_long = 447;
        unsafe {
            let fd = libc::syscall(SYS_MEMFD_SECRET, 0 as libc::c_uint);
            if fd < 0 {
                return None;
            }
            let fd = fd as libc::c_int;

            if libc::ftruncate(fd, size as libc::off_t) != 0 {
                libc::close(fd);
                return None;
            }

            let ptr = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);

            if ptr == libc::MAP_FAILED {
                return None;
            }
            Some(ptr as *mut u8)
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    None
}

#[cfg(not(target_os = "linux"))]
fn try_memfd_secret(_size: usize) -> Option<*mut u8> {
    None
}

/// Memory page protection: a buffer backed by mmap with page-level protections.
/// The buffer is mlock'd, excluded from core dumps, and can be toggled
/// between PROT_NONE (inaccessible) and PROT_READ (readable).
/// On drop, the buffer is securely zeroed, unlocked, and unmapped.
#[cfg(unix)]
pub struct ProtectedBuffer {
    ptr: *mut u8,
    len: usize,
    mapped_len: usize,
}

// SAFETY: ProtectedBuffer manages its own memory via mmap/munmap.
// The pointer is not shared and access is controlled via mprotect.
#[cfg(unix)]
unsafe impl Send for ProtectedBuffer {}

#[cfg(unix)]
impl ProtectedBuffer {
    /// Create a new protected buffer containing a copy of `data`.
    /// Tries memfd_secret (Linux 5.14+) for kernel-invisible memory first,
    /// then falls back to regular mmap. Buffer is page-aligned, locked in RAM,
    /// and excluded from core dumps.
    pub fn new(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        if page_size == 0 {
            return None;
        }
        let mapped_len = data.len().div_ceil(page_size) * page_size;

        // Try memfd_secret first (Linux 5.14+): memory invisible even to kernel/root
        let ptr = if let Some(p) = try_memfd_secret(mapped_len) {
            p
        } else {
            // Fallback: regular anonymous mmap
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    mapped_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                return None;
            }
            p as *mut u8
        };

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            // Lock in RAM to prevent swapping to disk
            libc::mlock(ptr as *const libc::c_void, mapped_len);
            // Exclude from core dumps (Linux)
            #[cfg(target_os = "linux")]
            libc::madvise(ptr as *mut libc::c_void, mapped_len, libc::MADV_DONTDUMP);
        }

        Some(ProtectedBuffer {
            ptr,
            len: data.len(),
            mapped_len,
        })
    }

    /// Make the buffer completely inaccessible (PROT_NONE).
    /// Any read or write will cause SIGSEGV — the decrypted content cannot be
    /// read by memory dump tools while the buffer is protected.
    pub fn protect(&self) {
        unsafe {
            libc::mprotect(
                self.ptr as *mut libc::c_void,
                self.mapped_len,
                libc::PROT_NONE,
            );
        }
    }

    /// Make the buffer readable (PROT_READ) for accessing the content.
    pub fn unprotect_read(&self) {
        unsafe {
            libc::mprotect(
                self.ptr as *mut libc::c_void,
                self.mapped_len,
                libc::PROT_READ,
            );
        }
    }

    /// Get a read-only slice of the buffer contents.
    /// The buffer must be unprotected (call `unprotect_read()` first).
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[cfg(unix)]
impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        unsafe {
            // Make writable so we can zero
            libc::mprotect(
                self.ptr as *mut libc::c_void,
                self.mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
            );
            // Secure zero entire mapped region
            std::ptr::write_bytes(self.ptr, 0, self.mapped_len);
            libc::munlock(self.ptr as *const libc::c_void, self.mapped_len);
            libc::munmap(self.ptr as *mut libc::c_void, self.mapped_len);
        }
    }
}

/// Non-unix fallback: wraps a Vec<u8> with zeroize-on-drop.
#[cfg(not(unix))]
pub struct ProtectedBuffer {
    data: Vec<u8>,
}

#[cfg(not(unix))]
impl ProtectedBuffer {
    pub fn new(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        Some(ProtectedBuffer {
            data: data.to_vec(),
        })
    }
    pub fn protect(&self) {}
    pub fn unprotect_read(&self) {}
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(not(unix))]
impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
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

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(&[], &[]));
        assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"a", b"b"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer string"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn test_detect_sigtrap_doesnt_crash() {
        // In a normal test environment (no debugger), should return false
        let _ = detect_sigtrap();
    }

    #[test]
    fn test_detect_frida_doesnt_crash() {
        let result = detect_frida();
        // In a normal test environment, Frida should not be detected
        assert!(!result);
    }

    #[test]
    fn test_detect_parent_debugger_doesnt_crash() {
        // cargo test runs under cargo, not a debugger
        let _ = detect_parent_debugger();
    }

    #[test]
    fn test_rdtsc_timing() {
        let start = rdtsc_timestamp();
        // Should not trigger immediately with generous threshold
        assert!(!rdtsc_check_elapsed(start, 1_000_000_000));
    }

    #[test]
    fn test_detect_vm_doesnt_crash() {
        let _ = detect_vm();
    }

    #[test]
    fn test_protected_buffer_roundtrip() {
        let data = b"sensitive secret data for testing";
        if let Some(buf) = ProtectedBuffer::new(data) {
            assert_eq!(buf.as_slice(), data);
            buf.protect();
            buf.unprotect_read();
            assert_eq!(buf.as_slice(), data);
        }
        // If mmap fails (CI containers), that's OK — skip gracefully
    }

    #[test]
    fn test_protected_buffer_empty() {
        assert!(ProtectedBuffer::new(&[]).is_none());
    }
}
