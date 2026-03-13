//! rshc-runner: Native Rust runtime for rshc-compiled scripts.
//!
//! This binary is used as a stub: rshc copies it and appends an encrypted
//! payload to the end. At runtime, the runner reads the payload from its
//! own executable, decrypts the script, and exec's the target shell.

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::os::unix::process::CommandExt;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use rshc::payload::{self, Payload, FLAG_SETUID};
use rshc::rc4::Rc4;

fn die(me: &str, msg: &str) -> ! {
    eprintln!("{}: {}", me, msg);
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let me = args
        .first()
        .cloned()
        .or_else(|| env::var("_").ok())
        .unwrap_or_else(|| {
            eprintln!("E: neither argv[0] nor $_ works.");
            process::exit(1);
        });

    // Read payload from own executable
    let exe_path = env::current_exe().unwrap_or_else(|e| {
        die(&me, &format!("cannot find own executable: {}", e));
    });

    let file = File::open(&exe_path).unwrap_or_else(|e| {
        die(&me, &format!("{}", e));
    });
    let mut reader = BufReader::new(file);

    let payload = Payload::read_from_exe(&mut reader).unwrap_or_else(|e| {
        die(&me, &format!("invalid payload: {}", e));
    });
    drop(reader);

    // setuid(0) if requested
    if payload.flags & FLAG_SETUID != 0 {
        unsafe {
            libc::setuid(0);
        }
    }

    // Clone encrypted arrays
    let pswd = payload.arrays[payload::IDX_PSWD].clone();
    let mut msg1 = payload.arrays[payload::IDX_MSG1].clone();
    let mut date = payload.arrays[payload::IDX_DATE].clone();
    let mut shll = payload.arrays[payload::IDX_SHLL].clone();
    let mut inlo = payload.arrays[payload::IDX_INLO].clone();
    let mut xecc = payload.arrays[payload::IDX_XECC].clone();
    let mut lsto = payload.arrays[payload::IDX_LSTO].clone();
    let mut tst1 = payload.arrays[payload::IDX_TST1].clone();
    let mut chk1 = payload.arrays[payload::IDX_CHK1].clone();
    let mut msg2 = payload.arrays[payload::IDX_MSG2].clone();
    let mut rlax = payload.arrays[payload::IDX_RLAX].clone();
    let mut opts = payload.arrays[payload::IDX_OPTS].clone();
    let mut text = payload.arrays[payload::IDX_TEXT].clone();
    let mut tst2 = payload.arrays[payload::IDX_TST2].clone();
    let mut chk2 = payload.arrays[payload::IDX_CHK2].clone();

    // Decrypt — same sequence as codegen encryption and C runtime's xsh()
    let mut rc4 = Rc4::new();
    rc4.reset();
    rc4.key(&pswd);

    rc4.arc4(&mut msg1);
    rc4.arc4(&mut date);

    // Check expiry
    let date_str = bytes_to_str(&date);
    if !date_str.is_empty() {
        if let Ok(expiry) = date_str.parse::<i64>() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if expiry < now {
                let msg = bytes_to_str(&msg1);
                eprintln!("{}", msg);
                process::exit(1);
            }
        }
    }

    rc4.arc4(&mut shll);
    rc4.arc4(&mut inlo);
    rc4.arc4(&mut xecc);
    rc4.arc4(&mut lsto);
    rc4.arc4(&mut tst1);

    // Integrity check 1: key with decrypted tst1, decrypt chk1, compare
    rc4.key(&tst1);
    rc4.arc4(&mut chk1);
    if chk1.len() != tst1.len() || chk1 != tst1 {
        let msg = bytes_to_str(&tst1);
        die(&me, &msg);
    }

    rc4.arc4(&mut msg2);

    // Decrypt relax flag, then conditionally key_with_file
    rc4.arc4(&mut rlax);
    if !rlax.is_empty() && rlax[0] == 0 {
        let shll_str = bytes_to_str(&shll);
        if rc4.key_with_file(&shll_str).is_err() {
            die(&me, &shll_str);
        }
    }

    rc4.arc4(&mut opts);
    rc4.arc4(&mut text);
    rc4.arc4(&mut tst2);

    // Integrity check 2
    rc4.key(&tst2);
    rc4.arc4(&mut chk2);
    if chk2.len() != tst2.len() || chk2 != tst2 {
        let msg = bytes_to_str(&tst2);
        die(&me, &msg);
    }

    // Convert decrypted fields to strings
    let shll_str = bytes_to_str(&shll);
    let inlo_str = bytes_to_str(&inlo);
    let opts_str = bytes_to_str(&opts);
    let lsto_str = bytes_to_str(&lsto);
    let text_str = bytes_to_str(&text);

    // Prepend hide_z (4096) spaces to hide script in process listing
    let hide_z = 1usize << 12;
    let mut scrpt = " ".repeat(hide_z);
    scrpt.push_str(&text_str);

    // Build command: shll [opts] [inlo] scrpt [lsto] argv[0] [argv[1]...]
    // argv[0] after the script becomes $0 for the shell (bash -c "script" $0 $1 ...)
    let mut cmd = std::process::Command::new(&shll_str);
    cmd.arg0(&me);

    if !opts_str.is_empty() {
        cmd.arg(&opts_str);
    }
    if !inlo_str.is_empty() {
        cmd.arg(&inlo_str);
    }
    cmd.arg(&scrpt);
    if !lsto_str.is_empty() {
        cmd.arg(&lsto_str);
    }
    // Pass argv[0] (binary name) as $0 for the shell, then remaining args
    for arg in &args {
        cmd.arg(arg);
    }

    // Replace this process with the shell (never returns on success)
    let err = cmd.exec();
    eprintln!("{}: {}: {}", me, shll_str, err);
    process::exit(1);
}

/// Convert null-terminated byte slice to string, stripping the trailing \0.
fn bytes_to_str(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    s.trim_end_matches('\0').to_string()
}
