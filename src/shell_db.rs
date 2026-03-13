/// Known shell database entry.
/// Matches shellsDB[] in shc.c:989-1008.
pub struct ShellEntry {
    pub shll: &'static str,
    pub inlo: &'static str,
    pub lsto: &'static str,
    pub xecc: &'static str,
}

pub static SHELLS_DB: &[ShellEntry] = &[
    ShellEntry { shll: "perl", inlo: "-e", lsto: "--",  xecc: "exec('%s',@ARGV);" },
    ShellEntry { shll: "rc",   inlo: "-c", lsto: "",    xecc: "builtin exec %s $*" },
    ShellEntry { shll: "sh",   inlo: "-c", lsto: "",    xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "dash", inlo: "-c", lsto: "",    xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "bash", inlo: "-c", lsto: "",    xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "zsh",  inlo: "-c", lsto: "",    xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "bsh",  inlo: "-c", lsto: "",    xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "Rsh",  inlo: "-c", lsto: "",    xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "ksh",  inlo: "-c", lsto: "",    xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "tsh",  inlo: "-c", lsto: "--",  xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "ash",  inlo: "-c", lsto: "--",  xecc: "exec '%s' \"$@\"" },
    ShellEntry { shll: "csh",  inlo: "-c", lsto: "-b",  xecc: "exec '%s' $argv" },
    ShellEntry { shll: "tcsh", inlo: "-c", lsto: "-b",  xecc: "exec '%s' $argv" },
];
