use std::io::Write;

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::noise::{rand_chr, rand_mod};
use crate::rc4::Rc4;
use crate::script::ShellInfo;

static RTC_CODE: &str = include_str!("rtc_code.c");

pub struct CodegenOptions {
    pub setuid: bool,
    pub debugexec: bool,
    pub traceable: bool,
    pub hardening: bool,
    pub busybox: bool,
    pub mmap2: bool,
}

/// All inputs needed to generate the compiled C output.
pub struct CompileJob<'a> {
    pub file: &'a str,
    pub date: &'a str,
    pub mail: &'a str,
    pub shell: &'a ShellInfo,
    pub text: &'a [u8],
    pub relax: bool,
    pub options: CodegenOptions,
    pub argv_str: &'a str,
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

    writeln!(o)?;
    write!(o, "#define      {}_z\t{}", name, l)?;
    writeln!(o)?;
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
pub fn write_c(job: &CompileJob) -> anyhow::Result<String> {
    let mut rng = OsRng;

    // --- Prepare data items (matching write_C local variables) ---

    // msg1 = "has expired!\n" + mail + \0
    let mut msg1: Vec<u8> = format!("has expired!\n{}", job.mail).into_bytes();
    msg1.push(0);

    // date + \0
    let mut date_bytes: Vec<u8> = job.date.as_bytes().to_vec();
    date_bytes.push(0);

    let mut shll_bytes: Vec<u8> = job.shell.shll.as_bytes().to_vec();
    shll_bytes.push(0);

    let mut inlo_bytes: Vec<u8> = job.shell.inlo.as_bytes().to_vec();
    inlo_bytes.push(0);

    let mut xecc_bytes: Vec<u8> = job.shell.xecc.as_bytes().to_vec();
    xecc_bytes.push(0);

    let mut lsto_bytes: Vec<u8> = job.shell.lsto.as_bytes().to_vec();
    lsto_bytes.push(0);

    // tst1 / chk1 — integrity check pair
    let mut tst1: Vec<u8> = b"location has changed!\0".to_vec();
    let chk1_plain = tst1.clone();

    // msg2
    let mut msg2: Vec<u8> = b"abnormal behavior!\0".to_vec();

    // rlax: 1 byte
    let mut rlax_bytes: Vec<u8> = vec![u8::from(job.relax)];
    let rlax_was_zero = rlax_bytes[0] == 0;

    let mut opts_bytes: Vec<u8> = job.shell.opts.as_bytes().to_vec();
    opts_bytes.push(0);

    let mut text_bytes: Vec<u8> = job.text.to_vec();
    text_bytes.push(0);

    // tst2 / chk2 — integrity check pair
    let mut tst2: Vec<u8> = b"shell has changed!\0".to_vec();
    let chk2_plain = tst2.clone();

    // --- Generate password and encrypt ---
    let mut pswd = [0u8; 256];
    rng.fill(&mut pswd[..]);

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
        rc4.key_with_file(&job.shell.shll)
            .map_err(|e| anyhow::anyhow!("rshc: invalid file name: {} {}", job.shell.shll, e))?;
    }

    rc4.arc4(&mut opts_bytes);
    rc4.arc4(&mut text_bytes);
    rc4.arc4(&mut tst2);

    // chk2: key with plaintext copy, then encrypt
    let mut chk2 = chk2_plain;
    rc4.key(&chk2);
    rc4.arc4(&mut chk2);

    // --- Output C file ---
    let output_path = format!("{}.x.c", job.file);
    let mut o = std::io::BufWriter::new(
        std::fs::File::create(&output_path)
            .map_err(|e| anyhow::anyhow!("rshc: creating output file: {} {}", output_path, e))?,
    );

    // Header comment
    writeln!(o, "#if 0")?;
    writeln!(
        o,
        "\trshc Version {}, Generic Shell Script Compiler",
        env!("CARGO_PKG_VERSION")
    )?;
    write!(o, "\tGNU GPL Version 3\n\n\t{}", job.argv_str)?;
    writeln!(o, "\n#endif\n")?;
    write!(o, "static  char data [] = ")?;

    // Build array of (data, name) references — 15 items indexed 0..14
    // Order matches the switch cases in shc.c:1264-1280
    let arrays: [(&[u8], &str); 15] = [
        (&pswd, "pswd"),       // 0
        (&msg1, "msg1"),       // 1
        (&date_bytes, "date"), // 2
        (&shll_bytes, "shll"), // 3
        (&inlo_bytes, "inlo"), // 4
        (&xecc_bytes, "xecc"), // 5
        (&lsto_bytes, "lsto"), // 6
        (&tst1, "tst1"),       // 7
        (&chk1, "chk1"),       // 8
        (&msg2, "msg2"),       // 9
        (&rlax_bytes, "rlax"), // 10
        (&opts_bytes, "opts"), // 11
        (&text_bytes, "text"), // 12
        (&tst2, "tst2"),       // 13
        (&chk2, "chk2"),       // 14
    ];

    // Emit arrays in random order (Fisher-Yates shuffle — O(n) vs previous O(n·Hn))
    let mut order: [usize; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    order.shuffle(&mut rng);

    let mut offset: usize = 0;
    for &idx in &order {
        let (data, name) = arrays[idx];
        prnt_array(&mut o, &mut rng, data, name, None, &mut offset)?;
    }

    // Footer
    write!(o, "\n/* End of data[] */;\n")?;
    writeln!(o, "#define      hide_z\t{}", 1u32 << 12)?;
    writeln!(
        o,
        "#define SETUID {}\t/* Define as 1 to call setuid(0) at start of script */",
        u8::from(job.options.setuid)
    )?;
    writeln!(
        o,
        "#define DEBUGEXEC\t{}\t/* Define as 1 to debug execvp calls */",
        u8::from(job.options.debugexec)
    )?;
    writeln!(
        o,
        "#define TRACEABLE\t{}\t/* Define as 1 to enable ptrace the executable */",
        u8::from(job.options.traceable)
    )?;
    writeln!(
        o,
        "#define HARDENING\t{}\t/* Define as 1 to disable ptrace/dump the executable */",
        u8::from(job.options.hardening)
    )?;
    writeln!(
        o,
        "#define BUSYBOXON\t{}\t/* Define as 1 to enable work with busybox */",
        u8::from(job.options.busybox)
    )?;
    writeln!(
        o,
        "#define MMAP2\t\t{}\t/* Define as 1 to use syscall mmap2 */",
        u8::from(job.options.mmap2)
    )?;

    // Write RTC code
    write!(o, "{}", RTC_CODE)?;

    o.flush()?;

    // Restrict permissions on generated C source (contains encrypted script data)
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o600))?;

    Ok(output_path)
}
