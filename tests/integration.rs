use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to create a temporary shell script from UTF-8 text.
fn create_script(content: &str) -> NamedTempFile {
    create_script_bytes(content.as_bytes())
}

/// Helper to create a temporary shell script from raw bytes (may be non-UTF-8).
fn create_script_bytes(content: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content).unwrap();
    f.flush().unwrap();
    f
}

/// Run a compiled binary and return its output, failing loudly if it cannot be
/// spawned. Never silently swallows a spawn error.
fn run_bin(path: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(path)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("could not execute {}: {}", path.display(), e))
}

/// Run a compiled binary, feeding `stdin_data` to its stdin. Used for password
/// prompts (read_password reads stdin, so no PTY is required).
fn run_bin_stdin(path: &std::path::Path, stdin_data: &[u8]) -> std::process::Output {
    use std::process::{Command, Stdio};
    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("could not spawn {}: {}", path.display(), e));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_data)
        .unwrap_or_else(|e| panic!("could not write stdin to {}: {}", path.display(), e));
    child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("could not wait for {}: {}", path.display(), e))
}

/// Assert a binary ran successfully and printed `needle`.
fn assert_runs_with(path: &std::path::Path, args: &[&str], needle: &str) {
    let out = run_bin(path, args);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "binary {} exited with failure (stderr: {})",
        path.display(),
        stderr
    );
    assert!(
        stdout.contains(needle),
        "expected '{}' in output of {}, got: {} (stderr: {})",
        needle,
        path.display(),
        stdout,
        stderr
    );
}

// ============================================================
// CLI flag tests
// ============================================================

#[test]
fn test_version_flag() {
    Command::cargo_bin("rshc")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("rshc"));
}

#[test]
fn test_license_flag() {
    Command::cargo_bin("rshc")
        .unwrap()
        .arg("-C")
        .assert()
        .success();
}

#[test]
fn test_abstract_flag() {
    Command::cargo_bin("rshc")
        .unwrap()
        .arg("-A")
        .assert()
        .success();
}

#[test]
fn test_missing_file_flag() {
    Command::cargo_bin("rshc").unwrap().assert().failure();
}

#[test]
fn test_nonexistent_script() {
    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", "/nonexistent/script.sh"])
        .assert()
        .failure();
}

// ============================================================
// Native mode compilation tests
// ============================================================

#[test]
fn test_native_compile_basic() {
    let script = create_script("#!/bin/sh\necho hello\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_binary");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "hello");
}

#[test]
fn test_native_compile_with_args() {
    let script = create_script("#!/bin/sh\necho \"args: $1 $2\"\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_args");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());

    let out = run_bin(&outfile, &["first", "second"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "binary exited with failure");
    assert!(
        stdout.contains("first") && stdout.contains("second"),
        "expected args in output, got: {}",
        stdout
    );
}

#[test]
fn test_native_compile_with_relax() {
    let script = create_script("#!/bin/sh\necho relax\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_relax");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "relax");
}

#[test]
fn test_native_compile_untraceable() {
    // The headline anti-debug path (-U): FLAG_TRACEABLE == 0 so all the
    // ptrace/seccomp/timing checks run. Prove the binary still runs correctly.
    let script = create_script("#!/bin/sh\necho untraceable\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_untraceable");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-U",
            "-r",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "untraceable");
}

#[test]
fn test_native_compile_with_compress() {
    let script = create_script("#!/bin/sh\necho compressed\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_compress");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--compress",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "compressed");
}

#[test]
fn test_native_compile_with_aes() {
    let script = create_script("#!/bin/sh\necho aes_mode\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_aes");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--aes",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "aes_mode");
}

#[test]
fn test_native_compile_with_aes_and_compress() {
    let script = create_script("#!/bin/sh\necho aes_compress\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_aes_compress");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--aes",
            "--compress",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "aes_compress");
}

#[test]
fn test_native_compile_stdin_mode() {
    let script = create_script("#!/bin/sh\necho stdin_mode\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_stdin");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--stdin-mode",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "stdin_mode");
}

#[test]
fn test_native_compile_max_runs() {
    let script = create_script("#!/bin/sh\necho run\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_maxruns");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--max-runs",
            "2",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());

    // First two runs should succeed
    for _ in 0..2 {
        assert_runs_with(&outfile, &[], "run");
    }

    // Third run should fail (max runs exceeded)
    let out = run_bin(&outfile, &[]);
    assert!(!out.status.success(), "expected failure after max runs");

    // Clean up counter file
    let counter_file = format!("{}.runs", outfile.display());
    let _ = std::fs::remove_file(&counter_file);
}

#[test]
fn test_native_compile_verbose() {
    let script = create_script("#!/bin/sh\necho verbose\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_verbose");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "-v",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("native mode"));

    assert!(outfile.exists());
}

// ============================================================
// Byte-faithful native execution
// ============================================================

#[test]
#[cfg(unix)]
fn test_native_byte_faithful() {
    // A script body carrying non-UTF-8 bytes must round-trip byte-identically:
    // the old lossy String conversion would corrupt them into U+FFFD.
    // printf outputs the literal bytes M, 0xC3, '(', E.
    let script_bytes: &[u8] = b"#!/bin/sh\nprintf 'M\xc3\x28E'\n";
    let script = create_script_bytes(script_bytes);
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_byte_faithful");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--aes",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());

    let out = run_bin(&outfile, &[]);
    assert!(out.status.success(), "binary exited with failure");
    assert_eq!(
        out.stdout, b"M\xc3\x28E",
        "non-UTF-8 script bytes were not preserved: got {:?}",
        out.stdout
    );
}

// ============================================================
// Classic mode compilation tests
// ============================================================

#[test]
fn test_classic_compile_basic() {
    let script = create_script("#!/bin/sh\necho classic\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_classic");

    let result = Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-r",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert();

    // Classic mode requires `cc` to be installed; if it's not, just check rshc ran correctly
    // by verifying the .c file was generated
    let c_file = format!("{}.x.c", script.path().display());
    if std::path::Path::new(&c_file).exists() {
        // Cleanup generated C file
        let _ = std::fs::remove_file(&c_file);
        // If cc was available, the binary should exist and run
        if outfile.exists() {
            assert_runs_with(&outfile, &[], "classic");
        }
    } else {
        // If no C file was generated, there was an error earlier
        result.failure();
    }
}

// ============================================================
// Flag conflict tests
// ============================================================

#[test]
fn test_native_conflicts_with_hardening() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "-n", "-H"])
        .assert()
        .failure();
}

#[test]
fn test_native_conflicts_with_busybox() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "-n", "-B"])
        .assert()
        .failure();
}

#[test]
fn test_native_conflicts_with_target() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-t",
            "x86_64-unknown-linux-musl",
        ])
        .assert()
        .failure();
}

#[test]
fn test_aes_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "--aes"])
        .assert()
        .failure();
}

#[test]
fn test_compress_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "--compress"])
        .assert()
        .failure();
}

#[test]
fn test_stdin_mode_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "--stdin-mode"])
        .assert()
        .failure();
}

#[test]
fn test_password_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "-p"])
        .assert()
        .failure();
}

// ============================================================
// Expiration tests
// ============================================================

#[test]
fn test_native_compile_with_expiry_past() {
    let script = create_script("#!/bin/sh\necho expired\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_expired");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "-e",
            "01/01/2020",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());

    // Should fail because it's expired
    let out = run_bin(&outfile, &[]);
    assert!(!out.status.success(), "expected failure due to expiration");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("expired"),
        "expected 'expired' message, got: {}",
        stderr
    );
}

#[test]
fn test_native_compile_with_expiry_future() {
    let script = create_script("#!/bin/sh\necho not_expired\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_not_expired");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "-e",
            "01/01/2030",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "not_expired");
}

// ============================================================
// Expiry date parsing tests
// ============================================================

#[test]
fn test_invalid_expiry_format() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-e",
            "invalid-date",
        ])
        .assert()
        .failure();
}

// ============================================================
// All features combined test
// ============================================================

#[test]
fn test_native_all_features_combined() {
    let script = create_script("#!/bin/sh\necho all_features\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_all");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--aes",
            "--compress",
            "--stdin-mode",
            "--max-runs",
            "100",
            "-e",
            "01/01/2030",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "all_features");

    // Clean up
    let counter_file = format!("{}.runs", outfile.display());
    let _ = std::fs::remove_file(&counter_file);
}

// ============================================================
// ChaCha20-Poly1305 tests
// ============================================================

#[test]
fn test_native_compile_with_chacha() {
    let script = create_script("#!/bin/sh\necho chacha_mode\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_chacha");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--chacha",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "chacha_mode");
}

#[test]
fn test_chacha_conflicts_with_aes() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "--aes",
            "--chacha",
        ])
        .assert()
        .failure();
}

#[test]
fn test_chacha_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "--chacha"])
        .assert()
        .failure();
}

#[test]
fn test_native_compile_chacha_with_compress() {
    let script = create_script("#!/bin/sh\necho chacha_compress\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_chacha_compress");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--chacha",
            "--compress",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());
    assert_runs_with(&outfile, &[], "chacha_compress");
}

// ============================================================
// Bind-host and no-network flag tests
// ============================================================

#[test]
fn test_no_network_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "--no-network"])
        .assert()
        .failure();
}

#[test]
fn test_bind_host_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "--bind-host"])
        .assert()
        .failure();
}

#[test]
fn test_native_compile_with_bind_host() {
    let script = create_script("#!/bin/sh\necho bound\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_bind_host");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--bind-host",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());

    // Binary should work on the same host it was built on
    assert_runs_with(&outfile, &[], "bound");
}

#[test]
fn test_native_compile_with_anti_vm() {
    let script = create_script("#!/bin/sh\necho antivm\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_anti_vm");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--anti-vm",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());

    // On a bare-metal host the VM check passes and the script runs. In a VM
    // (some CI) it exits refusing to run; accept that but require the refusal
    // message rather than a silent failure.
    let out = run_bin(&outfile, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        assert!(
            stdout.contains("antivm"),
            "expected 'antivm' in output, got: {}",
            stdout
        );
    } else {
        assert!(
            stderr.contains("unsupported environment"),
            "anti-vm binary failed unexpectedly (stderr: {})",
            stderr
        );
    }
}

#[test]
fn test_anti_vm_requires_native() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args(["-f", script.path().to_str().unwrap(), "--anti-vm"])
        .assert()
        .failure();
}

#[test]
#[cfg(target_os = "linux")]
fn test_native_compile_no_network() {
    let script = create_script("#!/bin/sh\necho no_net\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_no_net");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--no-network",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(outfile.exists());

    // unshare(CLONE_NEWNET) needs privileges. On a host that grants them the
    // script runs; in an unprivileged sandbox the runner refuses fast. Both
    // exercise the path — but fail loudly on any other kind of failure.
    let out = run_bin(&outfile, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        assert!(
            stdout.contains("no_net"),
            "expected 'no_net' in output, got: {}",
            stdout
        );
    } else {
        assert!(
            stderr.contains("network"),
            "no-network binary failed unexpectedly (stderr: {})",
            stderr
        );
    }
}

#[test]
fn test_bind_host_conflicts_with_password() {
    let script = create_script("#!/bin/sh\necho test\n");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "--bind-host",
            "-p",
        ])
        .assert()
        .failure();
}

// ============================================================
// Password protection round-trip
// ============================================================

#[test]
#[cfg(unix)]
fn test_native_password_roundtrip() {
    // Build with a password: read_password reads stdin, so the passphrase can be
    // piped (entry + confirmation) — no PTY needed.
    let script = create_script("#!/bin/sh\necho password_ok\n");
    let outdir = tempfile::tempdir().unwrap();
    let outfile = outdir.path().join("test_password");

    Command::cargo_bin("rshc")
        .unwrap()
        .args([
            "-f",
            script.path().to_str().unwrap(),
            "-n",
            "-r",
            "-p",
            "-o",
            outfile.to_str().unwrap(),
        ])
        .write_stdin("s3cr3t-pass\ns3cr3t-pass\n")
        .assert()
        .success();

    assert!(outfile.exists());

    // Correct password → runs and prints the marker.
    let ok = run_bin_stdin(&outfile, b"s3cr3t-pass\n");
    let stdout = String::from_utf8_lossy(&ok.stdout);
    assert!(
        ok.status.success(),
        "correct password should run (stderr: {})",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(
        stdout.contains("password_ok"),
        "expected 'password_ok' in output, got: {}",
        stdout
    );

    // Wrong password → refuses with a non-zero exit and does not run the script.
    let bad = run_bin_stdin(&outfile, b"wrong-pass\n");
    assert!(
        !bad.status.success(),
        "wrong password must not run the script"
    );
    assert!(
        !String::from_utf8_lossy(&bad.stdout).contains("password_ok"),
        "wrong password must not print the script output"
    );
}
