use anyhow::{bail, Result};

use crate::shell_db::SHELLS_DB;

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
    let text = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("rshc: {}: {}", path, e))?;

    // Check current System ARG_MAX limit
    let arg_max = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
    if arg_max > 0 && text.len() as f64 > 0.80 * arg_max as f64 {
        eprintln!(
            "rshc: WARNING!!\n\
             Scripts of length near to (or higher than) the current System limit on\n\
             \"maximum size of arguments to EXEC\", could comprise its binary execution.\n\
             In the current System the call sysconf(_SC_ARG_MAX) returns {} bytes\n\
             and your script \"{}\" is {} bytes length.",
            arg_max, path, text.len()
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
        if t.is_empty() { None } else { Some(t.to_string()) }
    });
    if third.is_some() {
        bail!("rshc: invalid first line in script: {}", first_line);
    }

    if shll.is_empty() || !shll.contains('/') {
        bail!("rshc: invalid shll");
    }

    let shell_name = shll.rsplit('/').next().unwrap();
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
        anyhow::anyhow!(
            "rshc Unknown shell ({}): specify [-i][-x][-l]",
            shell_name
        )
    })?;
    let xecc = xecc.ok_or_else(|| {
        anyhow::anyhow!(
            "rshc Unknown shell ({}): specify [-i][-x][-l]",
            shell_name
        )
    })?;
    let lsto = lsto.ok_or_else(|| {
        anyhow::anyhow!(
            "rshc Unknown shell ({}): specify [-i][-x][-l]",
            shell_name
        )
    })?;

    if verbose {
        eprintln!("rshc [-i]={}", inlo);
        eprintln!("rshc [-x]={}", xecc);
        eprintln!("rshc [-l]={}", lsto);
    }

    // Filter bogus opts
    let mut opts = opts_raw;
    if !opts.is_empty() && opts == lsto {
        eprintln!(
            "rshc opts={} : Is equal to [-l]. Removing opts",
            opts
        );
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
