# CLAUDE.md

## Project overview

rshc is a Rust reimplementation of [SHC (Shell Script Compiler)](https://github.com/neurobin/shc). It compiles shell scripts into encrypted binaries via two modes:

1. **Classic mode** (default): generates a C source file with an embedded RC4 decryption runtime, then compiles it with `cc`. Compatible with the original SHC.
2. **Native mode** (`-n`/`--native`): produces a standalone Rust binary with no C compiler dependency. The pre-compiled `rshc-runner` stub is copied and the encrypted payload is appended. Includes enhanced security features.

Security hardening features in native mode inspired by [chenyukang/rshc](https://github.com/chenyukang/rshc).

## Build & test

```bash
cargo build --release          # builds both rshc and rshc-runner
cargo test                     # unit + integration tests (117 tests)
cargo clippy -- -D warnings    # lint — MUST pass before pushing (CI enforces -D warnings)
cargo fmt -- --check           # format check

# Integration tests (requires shells: bash, dash, ksh, zsh, csh, tcsh, rc)
chmod +x tests/shell/ttest.sh
tests/shell/ttest.sh ./target/release/rshc
```

**Important**: Always run `cargo clippy -- -D warnings` locally before pushing. The CI runs clippy on Linux x86_64 which may have different lint behavior than macOS (e.g. `unsafe` blocks for intrinsics like `__cpuid`/`_rdtsc` that are safe on newer Rust versions). Use `#[allow(unused_unsafe)]` for cross-version compatibility.

Note: ksh tests fail on macOS arm64 due to Apple's bundled ksh93u+ (2012) segfaulting — not an rshc bug.

## Architecture

```
src/
  lib.rs        — Library crate: exports rc4, payload, aes, chacha, security (shared between rshc and rshc-runner)
  main.rs       — Entry point, orchestrates the pipeline (classic or native)
  cli.rs        — CLI arg parsing (clap derive), expiry date parsing
  script.rs     — Script reading, shebang parsing, #!/usr/bin/env resolution
  shell_db.rs   — Static table of 14 known shells (bash, zsh, perl, fish, rc, etc.)
  rc4.rs        — Byte-compatible RC4 cipher (matches SHC's "Alleged RC4")
  noise.rs      — Random padding utilities (rand_mod, rand_chr)
  codegen.rs    — Encryption pipeline (encrypt_script) + C code generation (write_c)
  native.rs     — Native build path: text preprocessing + copies runner stub + appends encrypted payload
  compiler.rs   — Invokes cc/strip/chmod, cross-compilation support
  payload.rs    — Binary payload format V2: serialize/deserialize with trailer pattern + extended fields
  aes.rs        — AES-256-GCM encryption/decryption + key derivation
  chacha.rs     — ChaCha20-Poly1305 encryption/decryption
  security.rs   — Anti-debug (multi-layer), memory protection, constant-time ops, seccomp-BPF, VM detection, ProtectedBuffer, SHA-256, password handling
  rtc_code.c    — Embedded C runtime (~600 lines, included via include_str!)
  bin/
    rshc-runner.rs — Native runner binary: reads payload, multi-layer anti-debug, decrypts (RC4+AES), decompresses, protected memory, execvp
tests/
  integration.rs — Full pipeline integration tests using assert_cmd (36 tests)
```

**Classic pipeline**: parse CLI → read script → parse shebang → encrypt_script() → emit C file with random-ordered data[] → compile with cc → strip

**Native pipeline**: parse CLI → read script → parse shebang → preprocess_text (compress, AES) → encrypt_script() → copy rshc-runner → compute integrity hash → append serialized V2 payload → chmod

## Key implementation details

- RC4 encryption must be **byte-compatible** with SHC. The `Rc4` struct uses wrapping u8 arithmetic to match C unsigned char overflow.
- `key_with_file()` uses `libc::stat` to key the cipher with the shell binary's inode metadata. Used by both C runtime and native runner.
- In classic mode, the 15 encrypted arrays are emitted in **random order** into a single `data[]` with random padding — this is the core obfuscation.
- In native mode, the payload uses a trailer pattern (size at end, like ZIP/AppImage) so the runner can find it by reading the last 8 bytes of its own executable.
- `encrypt_script()` in codegen.rs is shared by both paths — it handles the full RC4 encryption sequence including integrity check pairs (tst1/chk1, tst2/chk2) and conditional `key_with_file`.
- `rtc_code.c` is the C runtime extracted from SHC's RTC[] array. It must not be modified without matching changes in codegen.rs.
- Cross-compilation (`-t` flag) derives the cross-compiler name from the target triple (e.g. `x86_64-unknown-linux-musl` → `x86_64-linux-musl-gcc`) and adds `-static` for musl targets. `CC`/`STRIP` env vars override.

## Native mode V2 features

### Encryption layers

- **AES-256-GCM** (`--aes`): Additional encryption layer on top of RC4. Key stored in extended pswd array.
- **ChaCha20-Poly1305** (`--chacha`): Alternative AEAD cipher, faster on ARM/CPUs without AES-NI.
- **Password protection** (`-p`): Argon2id-hashed password with salt, verified at runtime with constant-time comparison.
- **Compression** (`--compress`): Deflate compression of script text before encryption. Applied before AES, decompressed after AES decrypt in runner.

### Anti-debug & anti-analysis (multi-layer)

1. **ptrace detection**: PTRACE_TRACEME (Linux), PT_DENY_ATTACH (macOS)
2. **SIGTRAP handler test** (via sigaction): installs handler, raises SIGTRAP — debuggers intercept the signal so the handler never fires
3. **Frida detection**: scans /proc/self/maps for Frida artifacts + checks thread names (gum-js-loop, gmain, gdbus)
4. **Parent process inspection**: checks /proc/<ppid>/comm for known debuggers (gdb, lldb, strace, ltrace, radare2...)
5. **P_TRACED flag (macOS)**: sysctl-based trace detection using raw kinfo_proc
6. **TracerPid monitoring**: /proc/self/status check (Linux)
7. **Environment injection detection**: LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, GCONV_PATH, sanitizer options, DYLD_* vars
8. **RDTSC timing** (x86_64): CPU cycle counter detects single-stepping — impossible to fake without hardware modification
9. **Timer-based anti-debug**: wall-clock timing detects single-stepping (30s threshold)
10. **Seccomp-BPF** (Linux): after anti-debug checks pass, installs kernel-level filter blocking ptrace, process_vm_readv, process_vm_writev — prevents debugger attachment post-verification
11. **VM detection** (`--anti-vm`): CPUID hypervisor bit (x86_64) + DMI/SMBIOS checks (Linux)
12. **Core dump prevention**: RLIMIT_CORE=0 + PR_SET_DUMPABLE=0
13. **PR_SET_MDWE** (Linux 6.3+): deny write-execute memory — prevents code injection attacks

### Memory protection

- **ProtectedBuffer**: mmap-backed, page-aligned memory region for decrypted script text
  - Tries `memfd_secret` first (Linux 5.14+) for kernel-invisible memory — not accessible even to root via /proc/pid/mem
  - Falls back to regular mmap with `mlock()` (prevents swap) + `MADV_DONTDUMP` (excludes from core dumps)
  - `mprotect(PROT_NONE)` makes pages inaccessible between decryption and execution
  - `mprotect(PROT_READ)` re-enables access only at the instant of execution
  - On drop: secure zero + munlock + munmap
- **zeroize**: All sensitive buffers (keys, passwords, decrypted text) zeroed with volatile writes after use
- **Constant-time comparisons**: `subtle::ConstantTimeEq` for all password hash, integrity hash, and host binding comparisons — prevents timing side-channel attacks

### Other features

- **Stdin mode** (`--stdin-mode`): Pipes script via stdin instead of -c argument to hide from /proc/*/cmdline.
- **Max runs** (`--max-runs N`): Execution counter stored in .runs file alongside binary.
- **Host binding** (`--bind-host`): Binary bound to machine identity (hostname + machine-id/hardware UUID).
- **Network isolation** (`--no-network`): Linux unshare(CLONE_NEWNET) drops all network access before script execution.
- **Binary integrity**: SHA-256 hash of runner binary verified at startup.
- **Compile-time string encryption** (`obfstr`): all error messages encrypted at compile time with per-string random keys — zero plaintext in the binary (verified with `strings`). Replaces the old XOR approach.
- **Debug exec** (`-D`): Prints exec details when flag is set.

### Pre-processing order

Build: raw_text → compress → AES encrypt → RC4 encrypt (via encrypt_script)
Runner: RC4 decrypt → strip \0 sentinel → AES decrypt → decompress → ProtectedBuffer → execute

## Payload V2 format

```
[magic "RSHC_PAYLOAD_V2\0" (16)]
[flags (1)] [relax_was_zero (1)] [num_arrays (2 LE)]
[ext_flags (1)] [password_salt (32)] [password_hash (32)]
[aes_nonce (12)] [max_runs (4 LE)] [integrity_hash (32)]
[array_sizes (15 * 4 LE)] [array_data...] [payload_size (8 LE)]
```

ext_flags bits: AES(0x01), PASSWORD(0x02), COMPRESSED(0x04), STDIN_MODE(0x08), CHACHA(0x10), NO_NETWORK(0x20), BIND_HOST(0x40), ANTI_VM(0x80)

Backward compatible: reader detects V1 magic and skips extended fields.

## Release profile

Release binaries are compiled with:
- `panic = "abort"` — no unwind info, reduces binary size and eliminates source path leakage from panic messages
- `strip = true` — removes all symbol tables and debug info
- `lto = true` — link-time optimization merges all crates into a single compilation unit, making the binary harder to analyze
- `codegen-units = 1` — single codegen unit for maximum LTO effectiveness and reduced timing side-channels

## Versioning

Managed by semantic-release. The `.version-hook.sh` script updates the version in `Cargo.toml` during release. All other files use `env!("CARGO_PKG_VERSION")` — do not manually bump version numbers.

## CI/CD

- **ci.yml**: build, unit tests, integration tests (Linux), clippy, fmt, macOS smoke test
- **release.yml**: matrix build (linux-x64, macos-x64, macos-arm64), semantic-release, upload binaries
- Homebrew formula auto-updated daily in `maxgfr/homebrew-tap` via `update-rshc.yml`
