# rshc — Rust Shell Script Compiler

[![CI](https://github.com/maxgfr/rshc/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/rshc/actions/workflows/ci.yml)

A Rust reimplementation of [SHC (Shell Script Compiler)](https://github.com/neurobin/shc). Takes a shell script, encrypts it, and compiles it into a self-contained binary that decrypts and executes the script at runtime.

Two compilation modes are available:
- **Classic** (default): generates C code + compiles with `cc` — compatible with the original SHC
- **Native** (`-n`): produces a standalone Rust binary — **no C compiler required**, with enhanced security features

## Install

### Homebrew (macOS / Linux)

```bash
brew install maxgfr/tap/rshc
```

### From source

```bash
cargo install --path .
```

Or build manually:

```bash
cargo build --release
# binaries at target/release/rshc and target/release/rshc-runner
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/maxgfr/rshc/releases) — available for Linux x64, macOS x64, and macOS ARM64.

## Usage

```bash
rshc -f script.sh                    # compile script.sh -> script.sh.x (classic, needs cc)
rshc -f script.sh -n                 # compile using native Rust runner (no cc needed)
rshc -f script.sh -o binary          # custom output name
rshc -f script.sh -e 01/01/2025      # set expiration date
rshc -f script.sh -r                 # relax mode (redistributable binary)
rshc -f script.sh -U                 # untraceable binary
rshc -f script.sh -H                 # hardening mode (classic only)
rshc -f script.sh -v                 # verbose output
rshc -f script.sh -t x86_64-unknown-linux-musl  # cross-compile for Linux (classic only)

# Native mode enhanced features:
rshc -f script.sh -n --aes           # AES-256-GCM encryption (instead of RC4)
rshc -f script.sh -n -p              # password-protected binary (Argon2id)
rshc -f script.sh -n --compress      # compress script before encryption
rshc -f script.sh -n --stdin-mode    # pass script via stdin (hide from /proc)
rshc -f script.sh -n --max-runs 100  # limit to 100 executions
rshc -f script.sh -n --aes --compress -p  # combine multiple features
rshc -f script.sh -n --chacha             # ChaCha20-Poly1305 (fast on ARM)
rshc -f script.sh -n --bind-host          # bind binary to this machine
rshc -f script.sh -n --no-network         # drop network before exec (Linux)
rshc -f script.sh -n --anti-vm            # refuse to run inside a VM
rshc -f script.sh -n -U --aes --compress --anti-vm  # maximum security
```

### Options

| Flag | Description |
|------|-------------|
| `-f <script>` | Script file to compile (required) |
| `-o <file>` | Output binary name (default: `<script>.x`) |
| `-n` / `--native` | Use native Rust runner (no `cc` required) |
| `-e <dd/mm/yyyy>` | Expiration date |
| `-m <message>` | Message shown on expiration |
| `-t <target>` | Cross-compilation target triple (classic only) |
| `-i <opt>` | Inline option for the shell interpreter |
| `-x <cmd>` | Exec command (printf format) |
| `-l <opt>` | Last shell option |
| `-r` | Relax security — redistributable binary |
| `-v` | Verbose compilation |
| `-S` | Enable setuid(0) at start |
| `-D` | Debug exec calls |
| `-U` | Make binary untraceable (anti-ptrace + anti-debug) |
| `-H` | Hardening mode (classic only) |
| `-B` | Compile for BusyBox (classic only) |
| `-2` | Use mmap2 syscall (classic only) |
| `-p` / `--password` | Require password at runtime — Argon2id (native only) |
| `--aes` | Use AES-256-GCM encryption (native only) |
| `--chacha` | Use ChaCha20-Poly1305 encryption (native only, fast on ARM) |
| `--compress` | Compress script before encryption (native only) |
| `--stdin-mode` | Pass script via stdin (native only) |
| `--max-runs <N>` | Maximum number of executions (native only) |
| `--no-network` | Drop network access before execution (Linux, native only) |
| `--bind-host` | Bind binary to this machine's identity (native only) |
| `--anti-vm` | Refuse execution inside virtual machines (native only) |
| `-C` | Display license |
| `-A` | Display abstract |

### Native mode (`-n`)

Native mode produces a standalone binary without needing a C compiler. The `rshc-runner` binary (built alongside `rshc`) is used as a stub — the encrypted script payload is appended to it.

```bash
# No cc, no strip, no C toolchain needed
rshc -n -f script.sh -o compiled_script
./compiled_script arg1 arg2
```

### Security features (native mode)

#### Multi-layer encryption

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Base | RC4 (SHC-compatible) | Obfuscation + backward compatibility |
| Optional | AES-256-GCM (`--aes`) | Authenticated encryption + tamper detection |
| Optional | ChaCha20-Poly1305 (`--chacha`) | AEAD, faster on ARM/CPUs without AES-NI |
| Integrity | Randomized per-build test strings | Prevents known-plaintext attacks on RC4 |

#### Anti-debug & anti-tamper

- **ptrace detection**: `PTRACE_TRACEME` (Linux), `PT_DENY_ATTACH` (macOS)
- **SIGTRAP handler test** (via `sigaction`): signal-based debugger detection — installs a SIGTRAP handler and verifies it runs (debuggers intercept SIGTRAP, so the handler never fires)
- **Frida detection**: scans `/proc/self/maps` for Frida artifacts and thread names (`gum-js-loop`, `gmain`, `gdbus`)
- **Parent process inspection**: checks if the parent process is a known debugger (gdb, lldb, strace, ltrace, radare2, etc.)
- **TracerPid monitoring**: `/proc/self/status` check (Linux)
- **P_TRACED flag**: sysctl-based trace detection (macOS)
- **RDTSC timing**: CPU cycle counter detects single-stepping (x86_64) — impossible to fake without hardware modification
- **Timer-based anti-debug**: wall-clock timing detects single-stepping (30s threshold)
- **Environment injection detection**: `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `GCONV_PATH`, `LSAN_OPTIONS`, `ASAN_OPTIONS`, `UBSAN_OPTIONS`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`
- **Seccomp-BPF syscall filter** (Linux): blocks `ptrace`, `process_vm_readv`, `process_vm_writev` at kernel level after anti-debug checks — prevents debugger attachment post-verification
- **Core dump prevention**: `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0` (verified)
- **Binary integrity**: SHA-256 self-checksum detects tampering
- **Runner symlink check**: prevents binary substitution attacks
- **Constant-time comparisons**: all password/hash/integrity comparisons use `subtle::ConstantTimeEq` to prevent timing side-channel attacks
- **PR_SET_MDWE** (Linux 6.3+): denies write-execute memory mappings, blocking code injection attacks
- **VM/hypervisor detection** (`--anti-vm`): CPUID hypervisor bit (x86_64) and DMI/SMBIOS checks (Linux) detect VMware, VirtualBox, KVM, Hyper-V, Xen, Parallels

#### Password protection (`-p`)

Passwords are hashed with **Argon2id** (memory-hard, GPU/ASIC-resistant):

```bash
rshc -n -f script.sh -p -r
# Prompts: Enter password / Confirm password

./script.sh.x
# Prompts: Password:
```

Parameters: 19 MB memory, 2 iterations, 1 parallelism — secure against dictionary attacks even with captured binaries.

#### Process hiding

- **Default mode**: 4096-space prefix hides script in process listings
- **Stdin mode** (`--stdin-mode`): pipes script via stdin — invisible in `/proc/*/cmdline`

#### Anti-forensics & memory protection

- **mmap-backed protected memory**: decrypted script stored in a dedicated mmap region with `PROT_NONE` ↔ `PROT_READ` toggling — memory dumps see inaccessible pages. On Linux 5.14+, uses `memfd_secret` for kernel-invisible memory (not accessible even to root via `/proc/pid/mem`)
- **mlock**: Sensitive buffers (keys, decrypted text) locked in RAM to prevent swapping to disk
- **MADV_DONTDUMP**: Sensitive memory excluded from core dumps (Linux)
- **zeroize**: All sensitive data zeroed after use (keys, decrypted script, passwords) using volatile writes that cannot be optimized away
- **Minimal plaintext window**: script is decrypted into a ProtectedBuffer, protected (PROT_NONE), and only unprotected at the instant of execution
- **Compile-time string encryption** (`obfstr`): all error messages encrypted at compile time with per-string random keys — zero plaintext strings in the binary (verified with `strings`)

#### Network & host isolation

- **Network namespace** (`--no-network`): Linux `unshare(CLONE_NEWNET)` drops all network access before script execution — prevents data exfiltration
- **Host binding** (`--bind-host`): Binary bound to machine identity (hostname + machine-id/hardware UUID) — won't run on a different machine

#### Execution limits

- **Expiration** (`-e`): binary refuses to run after a date
- **Max runs** (`--max-runs`): execution counter with `flock`-based file locking (race-condition resistant)

#### Compression (`--compress`)

Deflate compression before encryption — reduces binary size for large scripts.

### Supported shells

Automatically detected from the shebang line (`#!/bin/bash`, `#!/usr/bin/env zsh`, etc.):

bash, sh, dash, zsh, ksh, csh, tcsh, fish, ash, bsh, Rsh, tsh, rc, perl, powershell, pwsh, cmd

### Cross-compilation

The `-t` flag sets the C cross-compiler based on the target triple (classic mode only):

```bash
# Compile a script into a static Linux x86_64 binary (from macOS)
rshc -f script.sh -t x86_64-unknown-linux-musl

# Override the compiler with CC env var
CC=musl-gcc rshc -f script.sh -t x86_64-unknown-linux-musl
```

For musl targets, `-static` is automatically added to CFLAGS. Override with `CC` and `STRIP` environment variables.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CC` | `cc` (or derived from `-t`) | C compiler (classic mode) |
| `CFLAGS` | (none) | C compiler flags |
| `LDFLAGS` | (none) | Linker flags |
| `STRIP` | `strip` (or derived from `-t`) | Strip command |

## Security model

See [SECURITY.md](SECURITY.md) for the full threat model, including what rshc protects against and what it does not.

Release binaries are compiled with `panic = "abort"` (no unwind info), `strip = true` (no symbols), `lto = true` (link-time optimization), and `codegen-units = 1` (single compilation unit) — minimizing information available to reverse engineers.

**Summary**: rshc is an obfuscation tool, not DRM. It prevents casual source code extraction and raises the bar for reverse engineering, but a determined attacker with binary access can still recover the script via memory dumps or kernel-level tracing.

## Testing

```bash
# Unit tests (100+ tests)
cargo test

# Integration tests (26 tests covering native mode features)
cargo test --test integration

# Benchmarks (RC4, AES-256-GCM, Argon2id, compression, payload serialization)
cargo bench

# Fuzzing (requires cargo-fuzz and nightly Rust)
cargo +nightly fuzz run fuzz_payload_deserialize
cargo +nightly fuzz run fuzz_payload_from_exe
cargo +nightly fuzz run fuzz_rc4

# Integration tests with shell (requires shells to be installed)
chmod +x tests/shell/ttest.sh
tests/shell/ttest.sh ./target/release/rshc
```

Test coverage includes:
- RC4 encryption/decryption roundtrips
- AES-256-GCM encryption/decryption, key derivation, tamper detection (10 tests)
- Payload serialization V1/V2 formats, bounds checking, trailer pattern (13 tests)
- Security: Argon2id password hashing, SHA-256, XOR obfuscation, memory zeroing, symlink detection, anti-debug timer, constant-time eq, SIGTRAP, Frida, RDTSC, ProtectedBuffer, VM detection (27 tests)
- CLI flag parsing, conflicts, and date validation
- Full end-to-end pipeline: compilation + execution for native mode with all feature combinations

## How it works

### Classic mode (default)

1. Reads the script and parses the shebang to identify the shell
2. Generates a 256-byte random RC4 key + randomized integrity test strings
3. Encrypts the script text, shell path, options, and integrity check strings
4. Outputs a C file containing the encrypted data in random order with random padding
5. Embeds the C runtime (RC4 decryptor + `execvp` launcher)
6. Compiles with `cc`, strips the binary

### Native mode (`-n`)

1. Same encryption pipeline as classic mode (steps 1-3)
2. Optionally pre-processes text: compression (deflate), then AES-256-GCM encryption
3. Verifies runner binary is not a symlink
4. Serializes into V2 binary payload format with extended fields
5. Copies the runner stub, sets restrictive permissions (0o700) during build
6. Computes SHA-256 integrity hash of the runner
7. Appends the payload, sets final permissions (0o775)

At runtime:
1. Starts anti-debug timers (wall-clock + RDTSC cycle counter)
2. Disables core dumps (verified), sets `PR_SET_NO_NEW_PRIVS`
3. Multi-layer debugger detection: ptrace, SIGTRAP, Frida, parent process, env injection, TracerPid, RDTSC timing
4. Installs seccomp-BPF filter (blocks ptrace/process_vm_readv/writev)
5. VM detection if `--anti-vm` enabled (CPUID / DMI)
6. Verifies binary integrity (SHA-256)
7. Prompts for password if required (Argon2id, constant-time comparison)
8. Checks host binding (constant-time comparison)
9. Checks execution count with file locking
10. Decrypts (RC4 → AES-GCM → decompress) into mmap-backed ProtectedBuffer
11. Protects decrypted text (PROT_NONE), zeros all intermediate buffers
12. Unprotects text at the instant of execution
13. Executes via `execvp` or stdin pipe

## Acknowledgments

This project is a Rust port of [**SHC**](https://github.com/neurobin/shc) by Md Jahidul Hamid, originally created by Francisco Garcia. The RC4 encryption, C runtime code, and overall architecture are directly derived from SHC.

The security hardening features in native mode (anti-debug detection, memory zeroing, XOR string obfuscation, binary integrity verification, password protection) are inspired by [**chenyukang/rshc**](https://github.com/chenyukang/rshc) by Yukang Chen.

SHC is licensed under the [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.html).

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
