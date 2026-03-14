# CLAUDE.md

## Project overview

rshc is a Rust reimplementation of [SHC (Shell Script Compiler)](https://github.com/neurobin/shc). It compiles shell scripts into encrypted binaries via two modes:

1. **Classic mode** (default): generates a C source file with an embedded RC4 decryption runtime, then compiles it with `cc`. Compatible with the original SHC.
2. **Native mode** (`-n`/`--native`): produces a standalone Rust binary with no C compiler dependency. The pre-compiled `rshc-runner` stub is copied and the encrypted payload is appended. Includes enhanced security features.

Security hardening features in native mode inspired by [chenyukang/rshc](https://github.com/chenyukang/rshc).

## Build & test

```bash
cargo build --release          # builds both rshc and rshc-runner
cargo test                     # unit + integration tests (80+ tests)
cargo clippy -- -D warnings    # lint
cargo fmt -- --check           # format check

# Integration tests (requires shells: bash, dash, ksh, zsh, csh, tcsh, rc)
chmod +x test/ttest.sh
test/ttest.sh ./target/release/rshc
```

Note: ksh tests fail on macOS arm64 due to Apple's bundled ksh93u+ (2012) segfaulting — not an rshc bug.

## Architecture

```
src/
  lib.rs        — Library crate: exports rc4, payload, aes, security (shared between rshc and rshc-runner)
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
  security.rs   — Anti-debug, memory zeroing, XOR obfuscation, SHA-256 hashing, password handling, integrity verification
  rtc_code.c    — Embedded C runtime (~600 lines, included via include_str!)
  bin/
    rshc-runner.rs — Native runner binary: reads payload, decrypts (RC4+AES), decompresses, execvp
tests/
  integration.rs — Full pipeline integration tests using assert_cmd
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

- **AES-256-GCM** (`--aes`): Additional encryption layer on top of RC4. Key stored in extended pswd array.
- **Password protection** (`-p`): SHA-256 hashed password with salt, verified at runtime before decryption.
- **Compression** (`--compress`): Deflate compression of script text before encryption. Applied before AES, decompressed after AES decrypt in runner.
- **Stdin mode** (`--stdin-mode`): Pipes script via stdin instead of -c argument to hide from /proc/*/cmdline.
- **Max runs** (`--max-runs N`): Execution counter stored in .runs file alongside binary.
- **Anti-debug**: PTRACE_TRACEME (Linux), PT_DENY_ATTACH (macOS), TracerPid check, LD_PRELOAD/DYLD_INSERT_LIBRARIES detection.
- **Memory zeroing**: All sensitive buffers zeroed with `zeroize` after use.
- **Binary integrity**: SHA-256 hash of runner binary verified at startup.
- **XOR string obfuscation**: Error messages encoded to avoid plaintext in binary.
- **Core dump prevention**: RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 for untraceable binaries.
- **Debug exec** (`-D`): Prints exec details when flag is set.

### Pre-processing order

Build: raw_text → compress → AES encrypt → RC4 encrypt (via encrypt_script)
Runner: RC4 decrypt → strip \0 sentinel → AES decrypt → decompress → execute

## Payload V2 format

```
[magic "RSHC_PAYLOAD_V2\0" (16)]
[flags (1)] [relax_was_zero (1)] [num_arrays (2 LE)]
[ext_flags (1)] [password_salt (32)] [password_hash (32)]
[aes_nonce (12)] [max_runs (4 LE)] [integrity_hash (32)]
[array_sizes (15 * 4 LE)] [array_data...] [payload_size (8 LE)]
```

Backward compatible: reader detects V1 magic and skips extended fields.

## Versioning

Managed by semantic-release. The `.version-hook.sh` script updates the version in `Cargo.toml` during release. All other files use `env!("CARGO_PKG_VERSION")` — do not manually bump version numbers.

## CI/CD

- **ci.yml**: build, unit tests, integration tests (Linux), clippy, fmt, macOS smoke test
- **release.yml**: matrix build (linux-x64, macos-x64, macos-arm64), semantic-release, upload binaries
- Homebrew formula auto-updated daily in `maxgfr/homebrew-tap` via `update-rshc.yml`
