use anyhow::{bail, Result};
use chrono::{Local, NaiveDate, TimeZone};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rshc", version, about = "Generic Shell Script Compiler")]
pub struct Cli {
    /// Expiration date in dd/mm/yyyy format
    #[arg(short = 'e')]
    pub expiry: Option<String>,

    /// Message to display upon expiration
    #[arg(
        short = 'm',
        default_value = "Please contact your provider jahidulhamid@yahoo.com"
    )]
    pub mail: String,

    /// File name of the script to compile
    #[arg(short = 'f', required_unless_present_any = ["show_license", "show_abstract"])]
    pub file: Option<String>,

    /// Inline option for the shell interpreter i.e: -e
    #[arg(short = 'i')]
    pub iopt: Option<String>,

    /// eXec command, as a printf format i.e: exec('%s',@ARGV);
    #[arg(short = 'x')]
    pub xecc: Option<String>,

    /// Last shell option i.e: --
    #[arg(short = 'l')]
    pub lopt: Option<String>,

    /// Output filename
    #[arg(short = 'o')]
    pub outfile: Option<String>,

    /// Relax security. Make a redistributable binary
    #[arg(short = 'r')]
    pub relax: bool,

    /// Verbose compilation
    #[arg(short = 'v')]
    pub verbose: bool,

    /// Switch ON setuid for root callable programs
    #[arg(short = 'S')]
    pub setuid: bool,

    /// Switch ON debug exec calls
    #[arg(short = 'D')]
    pub debugexec: bool,

    /// Make binary untraceable
    #[arg(short = 'U')]
    pub untraceable: bool,

    /// Hardening: extra security protection
    #[arg(short = 'H')]
    pub hardening: bool,

    /// Display license and exit
    #[arg(short = 'C')]
    pub show_license: bool,

    /// Display abstract and exit
    #[arg(short = 'A')]
    pub show_abstract: bool,

    /// Compile for busybox
    #[arg(short = 'B')]
    pub busybox: bool,

    /// Use the system call mmap2
    #[arg(short = '2')]
    pub mmap2: bool,

    /// Cross-compilation target triple (e.g. x86_64-unknown-linux-musl)
    #[arg(short = 't', long = "target")]
    pub target: Option<String>,
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
