# Security Model

## What rshc protects against

### Source code extraction (static analysis)
- Script text is encrypted with RC4 (classic + native) or RC4 + AES-256-GCM (native with `--aes`)
- Encrypted data is embedded in random order with random padding (classic mode)
- Binary payload format does not expose plaintext (native mode)

### Casual reverse engineering
- Integrity test strings are randomized per build (prevents known-plaintext attacks on RC4)
- Error messages in the runner are XOR-obfuscated (not visible via `strings`)
- AES-256-GCM provides authenticated encryption with tamper detection

### Debugging / tracing
- Anti-ptrace detection (PTRACE_TRACEME on Linux, PT_DENY_ATTACH on macOS)
- `/proc/self/status` TracerPid monitoring (Linux)
- Environment variable injection detection (LD_PRELOAD, LD_AUDIT, DYLD_INSERT_LIBRARIES, etc.)
- Timer-based anti-debug (detects single-stepping)
- Core dump prevention (RLIMIT_CORE=0, PR_SET_DUMPABLE=0)

### Binary tampering
- SHA-256 integrity hash of the runner binary, verified at startup
- AES-256-GCM provides ciphertext authentication (any modification detected)

### Unauthorized execution
- Password protection with Argon2id (memory-hard, GPU-resistant)
- Expiration dates
- Execution count limits with file locking

### Process inspection
- Stdin mode (`--stdin-mode`) hides script from `/proc/*/cmdline`
- 4096-space prefix hides script in process listings (default mode)

### Post-execution forensics
- All sensitive data (keys, decrypted script, passwords) is zeroed with `zeroize` after use

## What rshc does NOT protect against

### Determined reverse engineering
A sufficiently motivated attacker with full access to the binary **can** recover the script. rshc is an obfuscation tool, not a DRM system. Specifically:

- **Memory dumping**: The decrypted script exists in RAM during execution. Tools like `gdb`, `Frida`, or `/proc/*/mem` can read it.
- **Kernel-level tracing**: `eBPF`, `strace` (with modifications), or kernel modules can intercept the `execvp` call and capture the script.
- **Binary patching**: Anti-debug checks can be NOPped out in the binary.
- **Brute-force on RC4**: RC4 alone is not cryptographically strong. The `--aes` flag adds proper authenticated encryption.

### Supply chain attacks
- The `rshc-runner` binary is verified not to be a symlink, but no cryptographic signature verification is performed.
- Crypto dependencies are pinned to exact versions. Non-crypto dependencies use semver ranges.

### Side-channel attacks
- No protection against timing attacks on the decryption itself.
- The `.runs` counter file is visible on the filesystem.

### Known limitations
- `--bind-host` and `-p` (password) cannot be used together (enforced by clap). This is because both features use the same payload field. Use `--bind-host` OR `-p`, not both.
- `--no-network` requires Linux with `unshare(CLONE_NEWNET)` capability. Fails in some containers or restricted environments.
- `-U` (untraceable) may cause false positives in CI environments that set `ASAN_OPTIONS`, `LSAN_OPTIONS`, or similar sanitizer variables — these are treated as injection attempts.
- seccomp-BPF filtering is NOT implemented. The runner sets `PR_SET_NO_NEW_PRIVS` (prevents setuid escalation) but does not install a syscall filter. The C runtime's `-H` flag provides full seccomp-BPF in classic mode.
- `mlock()` may fail silently if the process has insufficient `RLIMIT_MEMLOCK`. Sensitive data may still be swapped to disk in constrained environments.

## Recommendations

| Use case | Recommended flags |
|----------|-------------------|
| Basic obfuscation | `rshc -f script.sh -n -r` |
| Strong encryption | `rshc -f script.sh -n -r --aes` |
| ARM device (no AES-NI) | `rshc -f script.sh -n -r --chacha` |
| Anti-debugging | `rshc -f script.sh -n -r -U` |
| Password-protected | `rshc -f script.sh -n -r -p --aes` |
| Machine-locked | `rshc -f script.sh -n --bind-host --aes` |
| No network exfiltration | `rshc -f script.sh -n -r --aes --no-network` |
| Max security (password) | `rshc -f script.sh -n -U -p --aes --compress --stdin-mode --no-network` |
| Max security (host-locked) | `rshc -f script.sh -n -U --bind-host --aes --compress --stdin-mode --no-network` |
| Time-limited | `rshc -f script.sh -n -r -e 01/01/2026 --aes` |
| Run-limited | `rshc -f script.sh -n -r --max-runs 100 --aes` |

## Reporting vulnerabilities

If you discover a security vulnerability, please open an issue at https://github.com/maxgfr/rshc/issues with the label `security`.
