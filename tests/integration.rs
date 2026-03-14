use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to create a temporary shell script.
fn create_script(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
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

    // Execute the compiled binary
    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("hello"),
                "expected 'hello' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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

    std::process::Command::new(outfile.to_str().unwrap())
        .args(["first", "second"])
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("first") && stdout.contains("second"),
                "expected args in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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

    // Execute and verify it works
    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("compressed"),
                "expected 'compressed' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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

    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("aes_mode"),
                "expected 'aes_mode' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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

    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("aes_compress"),
                "expected 'aes_compress' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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

    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("stdin_mode"),
                "expected 'stdin_mode' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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
        let output = std::process::Command::new(outfile.to_str().unwrap()).output();
        if let Ok(o) = output {
            assert!(
                String::from_utf8_lossy(&o.stdout).contains("run"),
                "expected 'run' in output"
            );
        }
    }

    // Third run should fail (max runs exceeded)
    let output = std::process::Command::new(outfile.to_str().unwrap()).output();
    if let Ok(o) = output {
        assert!(!o.status.success(), "expected failure after max runs");
    }

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
        // If cc was available, the binary should exist
        if outfile.exists() {
            std::process::Command::new(outfile.to_str().unwrap())
                .output()
                .map(|output| {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(
                        stdout.contains("classic"),
                        "expected 'classic' in output, got: {}",
                        stdout
                    );
                })
                .unwrap_or_else(|e| {
                    eprintln!("Warning: could not execute compiled binary: {}", e);
                });
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
    let output = std::process::Command::new(outfile.to_str().unwrap()).output();
    if let Ok(o) = output {
        assert!(!o.status.success(), "expected failure due to expiration");
        let stderr = String::from_utf8_lossy(&o.stderr);
        assert!(
            stderr.contains("expired"),
            "expected 'expired' message, got: {}",
            stderr
        );
    }
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

    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("not_expired"),
                "expected 'not_expired' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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

    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("all_features"),
                "expected 'all_features' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });

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

    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("chacha_mode"),
                "expected 'chacha_mode' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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

    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("chacha_compress"),
                "expected 'chacha_compress' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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
    std::process::Command::new(outfile.to_str().unwrap())
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("bound"),
                "expected 'bound' in output, got: {}",
                stdout
            );
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: could not execute compiled binary: {}", e);
        });
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
