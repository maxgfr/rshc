use anyhow::{bail, Result};

use crate::shell_db::SHELLS_DB;

/// Resolve a shell name to its full path by searching PATH (pure Rust, no fork/exec).
fn resolve_shell(name: &str) -> Result<String> {
    let paths = std::env::var_os("PATH").ok_or_else(|| anyhow::anyhow!("rshc: PATH not set"))?;

    // On Windows, also search for .exe extension
    #[cfg(windows)]
    let candidates: Vec<String> = vec![name.to_string(), format!("{}.exe", name)];
    #[cfg(not(windows))]
    let candidates: Vec<String> = vec![name.to_string()];

    for dir in std::env::split_paths(&paths) {
        for candidate_name in &candidates {
            let candidate = dir.join(candidate_name);
            if let Ok(meta) = std::fs::metadata(&candidate) {
                if meta.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if (meta.permissions().mode() & 0o111) == 0 {
                            continue;
                        }
                    }
                    return Ok(candidate.to_string_lossy().into_owned());
                }
            }
        }
    }
    bail!("rshc: shell '{}' not found in PATH", name)
}

pub struct ShellInfo {
    pub shll: String,
    pub opts: String,
    pub inlo: String,
    pub xecc: String,
    pub lsto: String,
}

/// Read script file contents.
/// Matches read_script() in shc.c:1077-1114.
pub fn read_script(path: &str) -> Result<Vec<u8>> {
    let text = std::fs::read(path).map_err(|e| anyhow::anyhow!("rshc: {}: {}", path, e))?;

    // Check current System ARG_MAX limit (Unix only)
    #[cfg(unix)]
    let arg_max = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
    #[cfg(not(unix))]
    let arg_max: i64 = -1; // No ARG_MAX on Windows
    if arg_max > 0 && text.len() as f64 > 0.80 * arg_max as f64 {
        eprintln!(
            "rshc: WARNING!!\n\
             Scripts of length near to (or higher than) the current System limit on\n\
             \"maximum size of arguments to EXEC\", could comprise its binary execution.\n\
             In the current System the call sysconf(_SC_ARG_MAX) returns {} bytes\n\
             and your script \"{}\" is {} bytes length.",
            arg_max,
            path,
            text.len()
        );
    }

    Ok(text)
}

/// Parse shebang and look up shell in database.
/// Matches eval_shell() in shc.c:1011-1075.
pub fn eval_shell(
    text: &[u8],
    cli_inlo: Option<&str>,
    cli_xecc: Option<&str>,
    cli_lsto: Option<&str>,
    verbose: bool,
) -> Result<ShellInfo> {
    // Find first line
    let first_line_end = text.iter().position(|&b| b == b'\n').unwrap_or(text.len());
    let first_line = std::str::from_utf8(&text[..first_line_end])
        .map_err(|_| anyhow::anyhow!("rshc: invalid first line in script"))?;

    // sscanf(ptr, " #!%s%s %c", shll, opts, opts)
    // The original C parses: optional whitespace, #!, shell path, optional opts
    let trimmed = first_line.trim_start();
    if !trimmed.starts_with("#!") {
        bail!("rshc: invalid first line in script: {}", first_line);
    }
    let after_shebang = trimmed[2..].trim_start();

    let mut parts = after_shebang.splitn(3, char::is_whitespace);
    let shll = parts.next().unwrap_or("").to_string();
    let opts_raw = parts.next().unwrap_or("").trim().to_string();
    // If there's a third token, the sscanf would have matched 3 items (i > 2) → error
    let third = parts.next().and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    });
    if third.is_some() {
        bail!("rshc: invalid first line in script: {}", first_line);
    }

    if shll.is_empty() || !shll.contains('/') {
        bail!("rshc: invalid shll");
    }

    // Handle #!/usr/bin/env <shell> — resolve the actual shell path
    let (shll, mut opts) = {
        let name = shll.rsplit('/').next().unwrap_or("");
        if name == "env" && !opts_raw.is_empty() {
            // The real shell name is in opts_raw (e.g. "bash", "zsh")
            let resolved = resolve_shell(&opts_raw)?;
            (resolved, String::new())
        } else {
            (shll, opts_raw)
        }
    };

    // Validate that the shell binary actually exists
    if !std::path::Path::new(&shll).exists() {
        bail!("rshc: shell '{}' not found", shll);
    }

    let shell_name = shll.rsplit('/').next().unwrap_or("");
    if verbose {
        eprintln!("rshc shll={}", shell_name);
    }

    // Look up shell in database
    let mut inlo = cli_inlo.map(String::from);
    let mut xecc = cli_xecc.map(String::from);
    let mut lsto = cli_lsto.map(String::from);

    for entry in SHELLS_DB {
        if shell_name == entry.shll {
            if inlo.is_none() {
                inlo = Some(entry.inlo.to_string());
            }
            if xecc.is_none() {
                xecc = Some(entry.xecc.to_string());
            }
            if lsto.is_none() {
                lsto = Some(entry.lsto.to_string());
            }
            break;
        }
    }

    let inlo = inlo.ok_or_else(|| {
        anyhow::anyhow!("rshc Unknown shell ({}): specify [-i][-x][-l]", shell_name)
    })?;
    let xecc = xecc.ok_or_else(|| {
        anyhow::anyhow!("rshc Unknown shell ({}): specify [-i][-x][-l]", shell_name)
    })?;
    let lsto = lsto.ok_or_else(|| {
        anyhow::anyhow!("rshc Unknown shell ({}): specify [-i][-x][-l]", shell_name)
    })?;

    if verbose {
        eprintln!("rshc [-i]={}", inlo);
        eprintln!("rshc [-x]={}", xecc);
        eprintln!("rshc [-l]={}", lsto);
    }

    // Filter bogus opts
    if !opts.is_empty() && opts == lsto {
        eprintln!("rshc opts={} : Is equal to [-l]. Removing opts", opts);
        opts = String::new();
    } else if opts == "-" {
        eprintln!("rshc opts={} : No real one. Removing opts", opts);
        opts = String::new();
    }

    if verbose {
        eprintln!("rshc opts={}", opts);
    }

    Ok(ShellInfo {
        shll,
        opts,
        inlo,
        xecc,
        lsto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_shell_sh() {
        let text = b"#!/bin/sh\necho hello\n";
        let info = eval_shell(text, None, None, None, false).unwrap();
        assert_eq!(info.shll, "/bin/sh");
        assert_eq!(info.inlo, "-c");
        assert!(info.opts.is_empty());
    }

    #[test]
    fn test_eval_shell_bash() {
        let text = b"#!/bin/bash\necho hello\n";
        let info = eval_shell(text, None, None, None, false).unwrap();
        assert_eq!(info.shll, "/bin/bash");
        assert_eq!(info.inlo, "-c");
        assert_eq!(info.xecc, "exec '%s' \"$@\"");
    }

    #[test]
    fn test_eval_shell_env_bash() {
        let text = b"#!/usr/bin/env bash\necho hello\n";
        let info = eval_shell(text, None, None, None, false).unwrap();
        // Should resolve to an actual path, not "/usr/bin/env"
        assert!(info.shll.ends_with("/bash"));
        assert_eq!(info.inlo, "-c");
    }

    #[test]
    fn test_eval_shell_no_shebang() {
        let text = b"echo hello\n";
        assert!(eval_shell(text, None, None, None, false).is_err());
    }

    #[test]
    fn test_eval_shell_empty_shebang() {
        let text = b"#!\n";
        assert!(eval_shell(text, None, None, None, false).is_err());
    }

    #[test]
    fn test_eval_shell_too_many_options() {
        let text = b"#!/bin/bash -e -x\necho hello\n";
        assert!(eval_shell(text, None, None, None, false).is_err());
    }

    #[test]
    fn test_eval_shell_nonexistent() {
        let text = b"#!/bin/nonexistent_shell_xyz\necho hello\n";
        assert!(eval_shell(text, None, None, None, false).is_err());
    }

    #[test]
    fn test_eval_shell_cli_overrides() {
        let text = b"#!/bin/sh\necho hello\n";
        let info = eval_shell(text, Some("-e"), Some("exec '%s'"), Some("--"), false).unwrap();
        assert_eq!(info.inlo, "-e");
        assert_eq!(info.xecc, "exec '%s'");
        assert_eq!(info.lsto, "--");
    }

    #[test]
    fn test_eval_shell_with_option() {
        let text = b"#!/bin/bash -e\necho hello\n";
        let info = eval_shell(text, None, None, None, false).unwrap();
        assert_eq!(info.shll, "/bin/bash");
        assert_eq!(info.opts, "-e");
    }

    #[test]
    fn test_resolve_shell_bash() {
        let path = resolve_shell("bash").unwrap();
        assert!(path.ends_with("/bash"));
        assert!(std::path::Path::new(&path).exists());
    }

    #[test]
    fn test_resolve_shell_nonexistent() {
        assert!(resolve_shell("nonexistent_shell_xyz_123").is_err());
    }
}
