use anyhow::{bail, Result};
use chrono::{Local, NaiveDate, TimeZone};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "rshc",
    version,
    about = "Generic Shell Script Compiler",
    long_about = "rshc compiles shell scripts into encrypted binaries.\n\n\
        The compiled binary decrypts and executes the original script at runtime, \
        protecting the source code from being read directly. Supports bash, zsh, dash, \
        ksh, fish, csh, tcsh, perl, python, ruby, node, rc, and more.",
    after_help = "\x1b[1mExamples:\x1b[0m\n  \
        rshc -f script.sh                    Compile script.sh → script.sh.x\n  \
        rshc -f script.sh -o binary          Compile with custom output name\n  \
        rshc -f script.sh -e 01/01/2026      Set expiration date\n  \
        rshc -f script.sh -r                 Make redistributable (no host binding)\n  \
        rshc -f script.sh -UH                Untraceable + hardened binary\n  \
        rshc -f script.sh -n                 Native mode (no C compiler needed)\n  \
        rshc -f script.sh -n --aes           Native mode with AES-256-GCM\n  \
        rshc -f script.sh -n -p              Native mode with password protection\n  \
        rshc -f script.sh -n --compress      Native mode with compression\n  \
        rshc -f script.sh -t x86_64-unknown-linux-musl   Cross-compile for musl"
)]
pub struct Cli {
    // -- Input / Output --
    /// Shell script file to compile
    #[arg(short = 'f', long = "file", help_heading = "Input/Output",
          required_unless_present_any = ["show_license", "show_abstract"])]
    pub file: Option<String>,

    /// Output binary path [default: <file>.x]
    #[arg(short = 'o', long = "output", help_heading = "Input/Output")]
    pub outfile: Option<String>,

    // -- Expiration --
    /// Set expiration date (format: dd/mm/yyyy)
    #[arg(
        short = 'e',
        long = "expiry",
        help_heading = "Expiration",
        value_name = "DATE"
    )]
    pub expiry: Option<String>,

    /// Message shown when the binary has expired
    #[arg(
        short = 'm',
        long = "message",
        help_heading = "Expiration",
        value_name = "TEXT",
        default_value = "Please contact your provider jahidulhamid@yahoo.com"
    )]
    pub mail: String,

    // -- Security --
    /// Make a redistributable binary (skip host-specific binding)
    #[arg(short = 'r', long = "relax", help_heading = "Security")]
    pub relax: bool,

    /// Make binary untraceable (anti-debugging)
    #[arg(short = 'U', long = "untraceable", help_heading = "Security")]
    pub untraceable: bool,

    /// Enable extra hardening protections
    #[arg(short = 'H', long = "hardening", help_heading = "Security")]
    pub hardening: bool,

    /// Enable setuid for root-callable programs
    #[arg(short = 'S', long = "setuid", help_heading = "Security")]
    pub setuid: bool,

    /// Require password at runtime to decrypt (native mode only)
    #[arg(
        short = 'p',
        long = "password",
        help_heading = "Security",
        conflicts_with_all = ["hardening", "busybox", "mmap2", "bind_host"],
        requires = "native"
    )]
    pub password: bool,

    // -- Compilation --
    /// Use native Rust runner instead of C compilation (no cc required)
    #[arg(short = 'n', long = "native", help_heading = "Compilation",
          conflicts_with_all = ["hardening", "busybox", "mmap2"])]
    pub native: bool,

    /// Cross-compilation target triple (e.g. x86_64-unknown-linux-musl)
    #[arg(
        short = 't',
        long = "target",
        help_heading = "Compilation",
        value_name = "TRIPLE",
        conflicts_with = "native"
    )]
    pub target: Option<String>,

    /// Compile for busybox environment
    #[arg(short = 'B', long = "busybox", help_heading = "Compilation")]
    pub busybox: bool,

    /// Use the mmap2 system call instead of mmap
    #[arg(short = '2', long = "mmap2", help_heading = "Compilation")]
    pub mmap2: bool,

    /// Use AES-256-GCM encryption instead of RC4 (native mode only)
    #[arg(long = "aes", help_heading = "Compilation", requires = "native")]
    pub aes: bool,

    /// Compress script before encryption (native mode only)
    #[arg(long = "compress", help_heading = "Compilation", requires = "native")]
    pub compress: bool,

    /// Maximum number of executions allowed (native mode only, 0 = unlimited)
    #[arg(
        long = "max-runs",
        help_heading = "Compilation",
        value_name = "N",
        default_value = "0",
        requires = "native"
    )]
    pub max_runs: u32,

    /// Pass script via stdin instead of -c argument (native mode only)
    #[arg(long = "stdin-mode", help_heading = "Compilation", requires = "native")]
    pub stdin_mode: bool,

    /// Use ChaCha20-Poly1305 encryption instead of AES-256-GCM (native mode only)
    #[arg(
        long = "chacha",
        help_heading = "Compilation",
        requires = "native",
        conflicts_with = "aes"
    )]
    pub chacha: bool,

    /// Drop network access before executing the script (Linux only, native mode)
    #[arg(long = "no-network", help_heading = "Security", requires = "native")]
    pub no_network: bool,

    /// Bind binary to this host's machine identity (native mode only, incompatible with -p)
    #[arg(
        long = "bind-host",
        help_heading = "Security",
        requires = "native",
        conflicts_with = "password"
    )]
    pub bind_host: bool,

    /// Detect and refuse execution inside virtual machines (native mode only)
    #[arg(long = "anti-vm", help_heading = "Security", requires = "native")]
    pub anti_vm: bool,

    // -- Shell options --
    /// Inline option passed to the shell interpreter (e.g. -e)
    #[arg(
        short = 'i',
        long = "inline-opt",
        help_heading = "Shell Options",
        value_name = "OPT"
    )]
    pub iopt: Option<String>,

    /// Exec command as a printf format (e.g. "exec('%s',@ARGV);")
    #[arg(
        short = 'x',
        long = "exec-cmd",
        help_heading = "Shell Options",
        value_name = "FMT"
    )]
    pub xecc: Option<String>,

    /// Last shell option before the script (e.g. --)
    #[arg(
        short = 'l',
        long = "last-opt",
        help_heading = "Shell Options",
        value_name = "OPT"
    )]
    pub lopt: Option<String>,

    // -- Debug & Info --
    /// Enable verbose compilation output
    #[arg(short = 'v', long = "verbose", help_heading = "Debug & Info")]
    pub verbose: bool,

    /// Enable debug exec calls
    #[arg(short = 'D', long = "debug-exec", help_heading = "Debug & Info")]
    pub debugexec: bool,

    /// Display license and exit
    #[arg(short = 'C', long = "license", help_heading = "Debug & Info")]
    pub show_license: bool,

    /// Display abstract and exit
    #[arg(short = 'A', long = "abstract", help_heading = "Debug & Info")]
    pub show_abstract: bool,
}

/// Parse a dd/mm/yyyy date string into a Unix timestamp string.
fn parse_expiry_str(s: &str) -> Result<String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 3 {
        bail!("rshc parse(-e {}): Not a valid value", s);
    }
    let day: u32 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("rshc parse(-e {}): Not a valid value", s))?;
    let month: u32 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("rshc parse(-e {}): Not a valid value", s))?;
    let year: i32 = parts[2]
        .parse()
        .map_err(|_| anyhow::anyhow!("rshc parse(-e {}): Not a valid value", s))?;
    let date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| anyhow::anyhow!("rshc parse(-e {}): Not a valid value", s))?;
    let datetime = date
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| anyhow::anyhow!("rshc parse(-e {}): invalid time", s))?;
    let local = Local
        .from_local_datetime(&datetime)
        .single()
        .ok_or_else(|| anyhow::anyhow!("rshc parse(-e {}): ambiguous datetime", s))?;
    Ok(format!("{}", local.timestamp()))
}

impl Cli {
    /// Parse the expiration date string into a Unix timestamp string.
    /// Matches the -e parsing in shc.c:769-787.
    pub fn parse_expiry(&self) -> Result<String> {
        match &self.expiry {
            None => Ok(String::new()),
            Some(s) => parse_expiry_str(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_expiry_valid() {
        let result = parse_expiry_str("01/06/2030").unwrap();
        let timestamp: i64 = result.parse().unwrap();
        assert!(timestamp > 0);
    }

    #[test]
    fn test_parse_expiry_invalid_format() {
        assert!(parse_expiry_str("2030-01-01").is_err());
    }

    #[test]
    fn test_parse_expiry_wrong_parts() {
        assert!(parse_expiry_str("01/2030").is_err());
    }

    #[test]
    fn test_parse_expiry_invalid_date() {
        assert!(parse_expiry_str("32/13/2030").is_err());
    }

    #[test]
    fn test_parse_expiry_non_numeric() {
        assert!(parse_expiry_str("ab/cd/efgh").is_err());
    }
}
