# CLAUDE.md

## Project overview

rshc is a Rust reimplementation of [SHC (Shell Script Compiler)](https://github.com/neurobin/shc). It compiles shell scripts into encrypted binaries via two modes:

1. **Classic mode** (default): generates a C source file with an embedded RC4 decryption runtime, then compiles it with `cc`. Compatible with the original SHC.
2. **Native mode** (`-n`/`--native`): produces a standalone Rust binary with no C compiler dependency. The pre-compiled `rshc-runner` stub is copied and the encrypted payload is appended.

## Build & test

```bash
cargo build --release          # builds both rshc and rshc-runner
cargo test                     # unit tests (26 tests: RC4, payload, encryption roundtrip, etc.)
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
  lib.rs        — Library crate: exports rc4 and payload (shared between rshc and rshc-runner)
  main.rs       — Entry point, orchestrates the pipeline (classic or native)
  cli.rs        — CLI arg parsing (clap derive), expiry date parsing
  script.rs     — Script reading, shebang parsing, #!/usr/bin/env resolution
  shell_db.rs   — Static table of 14 known shells (bash, zsh, perl, fish, rc, etc.)
  rc4.rs        — Byte-compatible RC4 cipher (matches SHC's "Alleged RC4")
  noise.rs      — Random padding utilities (rand_mod, rand_chr)
  codegen.rs    — Encryption pipeline (encrypt_script) + C code generation (write_c)
  native.rs     — Native build path: copies runner stub, appends encrypted payload
  compiler.rs   — Invokes cc/strip/chmod, cross-compilation support
  payload.rs    — Binary payload format: serialize/deserialize with trailer pattern
  rtc_code.c    — Embedded C runtime (~600 lines, included via include_str!)
  bin/
    rshc-runner.rs — Native runner binary: reads payload from own exe, decrypts, execvp
```

**Classic pipeline**: parse CLI → read script → parse shebang → encrypt_script() → emit C file with random-ordered data[] → compile with cc → strip

**Native pipeline**: parse CLI → read script → parse shebang → encrypt_script() → copy rshc-runner → append serialized payload → chmod

## Key implementation details

- RC4 encryption must be **byte-compatible** with SHC. The `Rc4` struct uses wrapping u8 arithmetic to match C unsigned char overflow.
- `key_with_file()` uses `libc::stat` to key the cipher with the shell binary's inode metadata. Used by both C runtime and native runner.
- In classic mode, the 15 encrypted arrays are emitted in **random order** into a single `data[]` with random padding — this is the core obfuscation.
- In native mode, the payload uses a trailer pattern (size at end, like ZIP/AppImage) so the runner can find it by reading the last 8 bytes of its own executable.
- `encrypt_script()` in codegen.rs is shared by both paths — it handles the full RC4 encryption sequence including integrity check pairs (tst1/chk1, tst2/chk2) and conditional `key_with_file`.
- `rtc_code.c` is the C runtime extracted from SHC's RTC[] array. It must not be modified without matching changes in codegen.rs.
- Cross-compilation (`-t` flag) derives the cross-compiler name from the target triple (e.g. `x86_64-unknown-linux-musl` → `x86_64-linux-musl-gcc`) and adds `-static` for musl targets. `CC`/`STRIP` env vars override.

## Native mode limitations (V1)

- No chkenv re-execution (process hiding is done via 4096-space prefix only, not via exec-based hiding like the C runtime)
- `-H` (hardening), `-B` (busybox), `-2` (mmap2) are incompatible with `--native` (enforced by clap)
- `-U` (untraceable) and `-D` (debugexec) flags are accepted but not yet implemented in the runner

## Versioning

Managed by semantic-release. The `.version-hook.sh` script updates the version in `Cargo.toml` during release. All other files use `env!("CARGO_PKG_VERSION")` — do not manually bump version numbers.

## CI/CD

- **ci.yml**: build, unit tests, integration tests (Linux), clippy, fmt, macOS smoke test
- **release.yml**: matrix build (linux-x64, macos-x64, macos-arm64), semantic-release, upload binaries
- Homebrew formula auto-updated daily in `maxgfr/homebrew-tap` via `update-rshc.yml`
