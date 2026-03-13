# rshc — Rust Shell Script Compiler

[![CI](https://github.com/maxgfr/rshc/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/rshc/actions/workflows/ci.yml)

A Rust reimplementation of [SHC (Shell Script Compiler)](https://github.com/neurobin/shc). Takes a shell script, encrypts it with RC4, and compiles it into a self-contained binary that decrypts and executes the script at runtime via `execvp`.

Two compilation modes are available:
- **Classic** (default): generates C code + compiles with `cc` — compatible with the original SHC
- **Native** (`-n`): produces a standalone Rust binary — **no C compiler required**

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
| `-U` | Make binary untraceable (anti-ptrace) |
| `-H` | Hardening mode (classic only) |
| `-B` | Compile for BusyBox (classic only) |
| `-2` | Use mmap2 syscall (classic only) |
| `-C` | Display license |
| `-A` | Display abstract |

### Native mode (`-n`)

Native mode produces a standalone binary without needing a C compiler. The `rshc-runner` binary (built alongside `rshc`) is used as a stub — the encrypted script payload is appended to it.

```bash
# No cc, no strip, no C toolchain needed
rshc -n -f script.sh -o compiled_script
./compiled_script arg1 arg2
```

Native mode supports `-e` (expiry), `-r` (relax), `-S` (setuid), `-U` (untraceable), `-v` (verbose). The C-specific flags (`-H`, `-B`, `-2`, `-t`) are not compatible with native mode.

### Supported shells

Automatically detected from the shebang line (`#!/bin/bash`, `#!/usr/bin/env zsh`, etc.):

bash, sh, dash, zsh, ksh, csh, tcsh, fish, ash, bsh, Rsh, tsh, rc, perl

### Cross-compilation

The `-t` flag sets the C cross-compiler based on the target triple (classic mode only):

```bash
# Compile a script into a static Linux x86_64 binary (from macOS)
rshc -f script.sh -t x86_64-unknown-linux-musl

# Override the compiler with CC env var
CC=musl-gcc rshc -f script.sh -t x86_64-unknown-linux-musl
```

For musl targets, `-static` is automatically added to CFLAGS. The cross-compiler is derived from the target (e.g. `x86_64-linux-musl-gcc`). Override with `CC` and `STRIP` environment variables.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CC` | `cc` (or derived from `-t`) | C compiler (classic mode) |
| `CFLAGS` | (none) | C compiler flags |
| `LDFLAGS` | (none) | Linker flags |
| `STRIP` | `strip` (or derived from `-t`) | Strip command |

## Testing

```bash
# Unit tests (26 tests)
cargo test

# Integration tests (requires shells to be installed)
chmod +x test/ttest.sh
test/ttest.sh ./target/release/rshc
```

The integration test suite (`test/ttest.sh`) is adapted from the original SHC project. It tests compilation and execution across all supported shells with various flag combinations (`-r`, `-v`, `-D`, `-S`).

## How it works

### Classic mode (default)

1. Reads the script and parses the shebang to identify the shell (supports `#!/usr/bin/env <shell>`)
2. Generates a 256-byte random RC4 key
3. Encrypts the script text, shell path, options, and integrity check strings
4. Outputs a C file containing the encrypted data in random order with random padding
5. Embeds the C runtime (RC4 decryptor + `execvp` launcher)
6. Compiles the C file with `cc`, strips the binary

### Native mode (`-n`)

1. Same encryption pipeline as classic mode (steps 1-3)
2. Serializes the encrypted data into a binary payload format
3. Copies the pre-compiled `rshc-runner` stub to the output path
4. Appends the payload to the end of the binary (trailer pattern)

At runtime, the binary reads the payload from its own executable, decrypts the script in memory, and passes it to the shell via `execvp(shell, ["-c", script, ...])`.

## Acknowledgments

This project is a Rust port of [**SHC**](https://github.com/neurobin/shc) by Md Jahidul Hamid, originally created by Francisco Garcia. The RC4 encryption, C runtime code, and overall architecture are directly derived from SHC. The test suite is adapted from SHC's own tests.

SHC is licensed under the [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.html).

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
