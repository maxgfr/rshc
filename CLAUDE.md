# CLAUDE.md

## Project overview

rshc is a Rust reimplementation of [SHC (Shell Script Compiler)](https://github.com/neurobin/shc). It takes a shell script, encrypts it with RC4, generates a C source file with an embedded decryption runtime, then compiles it into a stripped binary using `cc`. The Rust code replaces only the **compiler side** — the generated C output and runtime are compatible with the original SHC.

## Build & test

```bash
cargo build --release          # build release binary
cargo test                     # unit tests (RC4 roundtrip + identity)
cargo clippy -- -D warnings    # lint
cargo fmt -- --check           # format check

# Integration tests (requires shells: bash, dash, ksh, zsh, csh, tcsh, rc)
chmod +x test/ttest.sh
test/ttest.sh ./target/release/rshc
```

## Architecture

```
src/
  main.rs       — Entry point, orchestrates the pipeline
  cli.rs        — CLI arg parsing (clap derive), expiry date parsing
  script.rs     — Script reading, shebang parsing, #!/usr/bin/env resolution
  shell_db.rs   — Static table of 13 known shells (bash, zsh, perl, rc, etc.)
  rc4.rs        — Byte-compatible RC4 cipher (matches SHC's "Alleged RC4")
  noise.rs      — Random padding utilities (rand_mod, rand_chr, noise)
  codegen.rs    — C code generation: encryption, random array ordering, octal output
  compiler.rs   — Invokes cc/strip/chmod, cross-compilation support
  rtc_code.c    — Embedded C runtime (~600 lines, included via include_str!)
```

**Pipeline**: parse CLI -> read script -> parse shebang -> generate RC4 key -> encrypt all fields -> emit C file with random-ordered data[] -> compile with cc -> strip

## Key implementation details

- RC4 encryption must be **byte-compatible** with SHC. The `Rc4` struct uses wrapping u8 arithmetic to match C unsigned char overflow.
- `key_with_file()` uses `libc::stat` to key the cipher with the shell binary's inode metadata. Platform-specific field names (macOS vs Linux) are handled.
- The 15 encrypted arrays are emitted in **random order** into a single `data[]` with random padding — this is the core obfuscation.
- `rtc_code.c` is the C runtime extracted from SHC's RTC[] array. It must not be modified without matching changes in codegen.rs.
- Cross-compilation (`-t` flag) derives the cross-compiler name from the target triple (e.g. `x86_64-unknown-linux-musl` -> `x86_64-linux-musl-gcc`) and adds `-static` for musl targets. `CC`/`STRIP` env vars override.

## Versioning

Managed by semantic-release. The `.version-hook.sh` script updates version strings in `Cargo.toml`, `cli.rs`, `main.rs`, and `codegen.rs` during release. Do not manually bump version numbers.

## CI/CD

- **ci.yml**: build, unit tests, integration tests (Linux), clippy, fmt, macOS smoke test
- **release.yml**: matrix build (linux-x64, macos-x64, macos-arm64), semantic-release, upload binaries
- Homebrew formula auto-updated daily in `maxgfr/homebrew-tap` via `update-rshc.yml`
