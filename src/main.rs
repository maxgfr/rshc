mod cli;
mod codegen;
mod compiler;
mod native;
mod noise;
mod script;
mod shell_db;

use anyhow::Result;
use clap::Parser;

static COPYING: &[&str] = &[
    "Copying:",
    "",
    "    This program is free software; you can redistribute it and/or modify",
    "    it under the terms of the GNU General Public License as published by",
    "    the Free Software Foundation; either version 3 of the License, or",
    "    (at your option) any later version.",
    "",
    "    This program is distributed in the hope that it will be useful,",
    "    but WITHOUT ANY WARRANTY; without even the implied warranty of",
    "    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the",
    "    GNU General Public License for more details.",
    "",
    "    You should have received a copy of the GNU General Public License",
    "    along with this program; if not, write to the Free Software",
    "    @Neurobin, Dhaka, Bangladesh",
    "",
    "    Report problems and questions to:http://github.com/neurobin/shc",
    "",
];

static ABSTRACT: &[&str] = &[
    "Abstract:",
    "",
    "    This tool generates a stripped binary executable version",
    "    of the script specified at command line.",
    "",
    "    Binary version will be saved with a .x extension by default.",
    "    You can specify output file name too with [-o filname] option.",
    "",
    "    You can specify expiration date [-e] too, after which binary will",
    "    refuse to be executed, displaying \"[-m]\" instead.",
    "",
    "    You can compile whatever interpreted script, but valid [-i], [-x]",
    "    and [-l] options must be given.",
    "",
];

fn main() -> Result<()> {
    // Set LANG="" — matches shc.c:1357
    std::env::set_var("LANG", "");

    let args = cli::Cli::parse();

    // Handle -C (license)
    if args.show_license {
        eprintln!(
            "rshc Version {}, Generic Shell Script Compiler",
            env!("CARGO_PKG_VERSION")
        );
        eprintln!("GNU GPL Version 3");
        eprint!("rshc ");
        for line in COPYING {
            eprintln!("{}", line);
        }
        std::process::exit(0);
    }

    // Handle -A (abstract)
    if args.show_abstract {
        eprintln!(
            "rshc Version {}, Generic Shell Script Compiler",
            env!("CARGO_PKG_VERSION")
        );
        eprintln!("GNU GPL Version 3");
        eprint!("rshc ");
        for line in ABSTRACT {
            eprintln!("{}", line);
        }
        std::process::exit(0);
    }

    // From here on, -f is required (clap enforces this unless -C/-A)
    let file = args
        .file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("rshc: -f <file> is required"))?;

    // Parse expiration date
    let date = args.parse_expiry()?;
    if args.verbose && !date.is_empty() {
        eprintln!("rshc -e {}", date);
    }

    // Read script
    let text = script::read_script(file)?;

    // Evaluate shell
    let shell_info = script::eval_shell(
        &text,
        args.iopt.as_deref(),
        args.xecc.as_deref(),
        args.lopt.as_deref(),
        args.verbose,
    )?;

    let options = codegen::CodegenOptions {
        setuid: args.setuid,
        debugexec: args.debugexec,
        traceable: !args.untraceable,
        hardening: args.hardening,
        busybox: args.busybox,
        mmap2: args.mmap2,
    };

    if args.native {
        // Native Rust runner path — no C compiler needed
        let job = codegen::CompileJob {
            file,
            date: &date,
            mail: &args.mail,
            shell: &shell_info,
            text: &text,
            relax: args.relax,
            options,
            argv_str: "",
        };
        let encrypted = codegen::encrypt_script(&job)?;
        native::build_native(
            &encrypted,
            &job.options,
            file,
            args.outfile.as_deref(),
            args.verbose,
        )?;
    } else {
        // Classic C codegen + cc compilation path
        let argv_str = {
            let mut parts = vec!["rshc".to_string()];
            if let Some(ref e) = args.expiry {
                parts.push(format!("-e {}", e));
            }
            parts.push(format!("-f {}", file));
            if args.relax {
                parts.push("-r".to_string());
            }
            if args.verbose {
                parts.push("-v".to_string());
            }
            if args.setuid {
                parts.push("-S".to_string());
            }
            if args.debugexec {
                parts.push("-D".to_string());
            }
            if args.untraceable {
                parts.push("-U".to_string());
            }
            if args.hardening {
                parts.push("-H".to_string());
            }
            if args.busybox {
                parts.push("-B".to_string());
            }
            if args.mmap2 {
                parts.push("-2".to_string());
            }
            parts.join(" ")
        };

        let job = codegen::CompileJob {
            file,
            date: &date,
            mail: &args.mail,
            shell: &shell_info,
            text: &text,
            relax: args.relax,
            options,
            argv_str: &argv_str,
        };
        codegen::write_c(&job)?;

        compiler::make(
            file,
            args.outfile.as_deref(),
            args.verbose,
            args.target.as_deref(),
        )?;
    }

    Ok(())
}
