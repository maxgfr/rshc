use std::io::Write;

use rand::Rng;

use crate::noise::{rand_chr, rand_mod};
use crate::rc4::Rc4;

static RTC_CODE: &str = include_str!("rtc_code.c");

pub struct CodegenOptions {
    pub setuid: bool,
    pub debugexec: bool,
    pub traceable: bool,
    pub hardening: bool,
    pub busybox: bool,
    pub mmap2: bool,
}

/// Write bytes with random pre/post padding in octal escape format.
/// Matches prnt_bytes() in shc.c:1147-1163.
fn prnt_bytes(
    o: &mut impl Write,
    rng: &mut impl Rng,
    data: &[u8],
    m: usize,
    l: usize,
    n: usize,
) -> std::io::Result<()> {
    let total = m + l + n;
    for i in 0..total {
        if (i & 0xf) == 0 {
            write!(o, "\n\t\"")?;
        }
        let byte = if i >= m && i < m + l {
            data[i - m]
        } else {
            rand_chr(rng)
        };
        write!(o, "\\{:03o}", byte)?;
        if (i & 0xf) == 0xf {
            write!(o, "\"")?;
        }
    }
    if (total & 0xf) != 0 {
        write!(o, "\"")?;
    }
    Ok(())
}

/// Output one encrypted array with random padding and #define directives.
/// Matches prnt_array() in shc.c:1165-1176.
fn prnt_array(
    o: &mut impl Write,
    rng: &mut impl Rng,
    data: &[u8],
    name: &str,
    cast: Option<&str>,
    offset: &mut usize,
) -> std::io::Result<()> {
    let l = data.len();
    let m_base = rand_mod(rng, 1 + l as u32 / 4) as usize;
    let n = rand_mod(rng, 1 + l as u32 / 4) as usize;

    // Type alignment (only when cast is Some and l > 0)
    let m = if cast.is_some() && l > 0 {
        let a = (*offset + m_base) % l;
        if a != 0 {
            m_base + l - a
        } else {
            m_base
        }
    } else {
        m_base
    };

    write!(o, "\n")?;
    write!(o, "#define      {}_z\t{}", name, l)?;
    write!(o, "\n")?;
    write!(
        o,
        "#define      {}\t({}(&data[{}]))",
        name,
        cast.unwrap_or(""),
        *offset + m
    )?;
    prnt_bytes(o, rng, data, m, l, n)?;
    *offset += m + l + n;
    Ok(())
}

/// Generate the C output file with encrypted script data and runtime code.
/// Matches write_C() in shc.c:1184-1298.
#[allow(clippy::too_many_arguments)]
pub fn write_c(
    file: &str,
    date: &str,
    mail: &str,
    shll: &str,
    inlo: &str,
    xecc: &str,
    lsto: &str,
    opts: &str,
    text: &[u8],
    rlax: bool,
    options: &CodegenOptions,
    argv_str: &str,
) -> anyhow::Result<String> {
    let mut rng = rand::thread_rng();

    // --- Prepare data items (matching write_C local variables) ---

    // msg1 = "has expired!\n" + mail + \0
    let mut msg1: Vec<u8> = format!("has expired!\n{}", mail).into_bytes();
    msg1.push(0);

    // date + \0
    let mut date_bytes: Vec<u8> = date.as_bytes().to_vec();
    date_bytes.push(0);

    // Keep a copy of shll before encryption for key_with_file
    let kwsh = shll.to_string();
    let mut shll_bytes: Vec<u8> = shll.as_bytes().to_vec();
    shll_bytes.push(0);

    let mut inlo_bytes: Vec<u8> = inlo.as_bytes().to_vec();
    inlo_bytes.push(0);

    let mut xecc_bytes: Vec<u8> = xecc.as_bytes().to_vec();
    xecc_bytes.push(0);

    let mut lsto_bytes: Vec<u8> = lsto.as_bytes().to_vec();
    lsto_bytes.push(0);

    // tst1 / chk1 — integrity check pair
    let mut tst1: Vec<u8> = b"location has changed!\0".to_vec();
    let chk1_plain = tst1.clone();

    // msg2
    let mut msg2: Vec<u8> = b"abnormal behavior!\0".to_vec();

    // rlax: 1 byte
    let mut rlax_bytes: Vec<u8> = vec![if rlax { 1u8 } else { 0u8 }];
    let rlax_was_zero = rlax_bytes[0] == 0;

    let mut opts_bytes: Vec<u8> = opts.as_bytes().to_vec();
    opts_bytes.push(0);

    let mut text_bytes: Vec<u8> = text.to_vec();
    text_bytes.push(0);

    // tst2 / chk2 — integrity check pair
    let mut tst2: Vec<u8> = b"shell has changed!\0".to_vec();
    let chk2_plain = tst2.clone();

    // --- Generate password and encrypt ---
    // pswd_z = noise(pswd, pswd_z, 0, 0) → 256 random bytes
    let pswd: Vec<u8> = (0..256).map(|_| rng.gen::<u8>()).collect();

    let mut rc4 = Rc4::new();
    rc4.reset();
    rc4.key(&pswd);

    // Encrypt in exact same order as shc.c:1222-1243
    rc4.arc4(&mut msg1);
    rc4.arc4(&mut date_bytes);
    rc4.arc4(&mut shll_bytes);
    rc4.arc4(&mut inlo_bytes);
    rc4.arc4(&mut xecc_bytes);
    rc4.arc4(&mut lsto_bytes);
    rc4.arc4(&mut tst1);

    // chk1: key with plaintext copy, then encrypt
    let mut chk1 = chk1_plain;
    rc4.key(&chk1);
    rc4.arc4(&mut chk1);

    rc4.arc4(&mut msg2);

    // Save rlax_was_zero BEFORE encrypting rlax
    rc4.arc4(&mut rlax_bytes);

    // key_with_file conditional: check !rlax[0] BEFORE encryption, call AFTER
    if rlax_was_zero {
        rc4.key_with_file(&kwsh).map_err(|e| {
            anyhow::anyhow!("rshc: invalid file name: {} {}", kwsh, e)
        })?;
    }

    rc4.arc4(&mut opts_bytes);
    rc4.arc4(&mut text_bytes);
    rc4.arc4(&mut tst2);

    // chk2: key with plaintext copy, then encrypt
    let mut chk2 = chk2_plain;
    rc4.key(&chk2);
    rc4.arc4(&mut chk2);

    // --- Output C file ---
    let output_path = format!("{}.x.c", file);
    let mut o = std::io::BufWriter::new(
        std::fs::File::create(&output_path)
            .map_err(|e| anyhow::anyhow!("rshc: creating output file: {} {}", output_path, e))?,
    );

    // Header comment
    write!(o, "#if 0\n")?;
    write!(o, "\trshc Version 0.1.0, Generic Shell Script Compiler\n")?;
    write!(o, "\tGNU GPL Version 3\n\n\t")?;
    write!(o, "{}", argv_str)?;
    write!(o, "\n#endif\n\n")?;
    write!(o, "static  char data [] = ")?;

    // Build array of (data, name) tuples — 15 items indexed 0..14
    // Order matches the switch cases in shc.c:1264-1280
    let arrays: [(Vec<u8>, &str); 15] = [
        (pswd.clone(), "pswd"),   // 0
        (msg1, "msg1"),           // 1
        (date_bytes, "date"),     // 2
        (shll_bytes, "shll"),     // 3
        (inlo_bytes, "inlo"),     // 4
        (xecc_bytes, "xecc"),     // 5
        (lsto_bytes, "lsto"),     // 6
        (tst1, "tst1"),           // 7
        (chk1, "chk1"),           // 8
        (msg2, "msg2"),           // 9
        (rlax_bytes, "rlax"),     // 10
        (opts_bytes, "opts"),     // 11
        (text_bytes, "text"),     // 12
        (tst2, "tst2"),           // 13
        (chk2, "chk2"),           // 14
    ];

    // Random ordering — matches the fall-through switch in shc.c:1260-1283
    let mut emitted = [false; 15];
    let mut offset: usize = 0;
    let mut num_remaining: i32 = 15;

    while num_remaining > 0 {
        let start = rand_mod(&mut rng, 15) as usize;
        let mut idx = start;
        loop {
            if !emitted[idx] {
                let (ref data, name) = arrays[idx];
                // All arrays use cast=None in original (cast argument is always 0)
                prnt_array(&mut o, &mut rng, data, name, None, &mut offset)?;
                emitted[idx] = true;
                num_remaining -= 1;
                break;
            }
            idx = (idx + 1) % 15;
        }
    }

    // Footer
    write!(o, "\n/* End of data[] */;\n")?;
    writeln!(o, "#define      hide_z\t{}", 1u32 << 12)?;
    writeln!(
        o,
        "#define SETUID {}\t/* Define as 1 to call setuid(0) at start of script */",
        if options.setuid { 1 } else { 0 }
    )?;
    writeln!(
        o,
        "#define DEBUGEXEC\t{}\t/* Define as 1 to debug execvp calls */",
        if options.debugexec { 1 } else { 0 }
    )?;
    writeln!(
        o,
        "#define TRACEABLE\t{}\t/* Define as 1 to enable ptrace the executable */",
        if options.traceable { 1 } else { 0 }
    )?;
    writeln!(
        o,
        "#define HARDENING\t{}\t/* Define as 1 to disable ptrace/dump the executable */",
        if options.hardening { 1 } else { 0 }
    )?;
    writeln!(
        o,
        "#define BUSYBOXON\t{}\t/* Define as 1 to enable work with busybox */",
        if options.busybox { 1 } else { 0 }
    )?;
    writeln!(
        o,
        "#define MMAP2\t\t{}\t/* Define as 1 to use syscall mmap2 */",
        if options.mmap2 { 1 } else { 0 }
    )?;

    // Write RTC code
    write!(o, "{}", RTC_CODE)?;

    o.flush()?;
    Ok(output_path)
}
