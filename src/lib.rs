pub mod payload;
pub mod rc4;

#[cfg(test)]
mod tests {
    use crate::payload::{self, Payload, FLAG_TRACEABLE};
    use crate::rc4::Rc4;

    /// Full encryption/decryption roundtrip test matching the codegen→runner pipeline.
    /// Verifies that encrypting with codegen's sequence and decrypting with
    /// the runner's sequence recovers the original plaintext.
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // --- Simulate codegen encryption (same order as codegen::encrypt_script) ---
        let pswd: Vec<u8> = (0..=255).collect(); // deterministic password for test
        let orig_msg1 = b"has expired!\ntest@test.com\0".to_vec();
        let orig_date = b"\0".to_vec();
        let orig_shll = b"/bin/sh\0".to_vec();
        let orig_inlo = b"-c\0".to_vec();
        let orig_xecc = b"exec '%s' \"$@\"\0".to_vec();
        let orig_lsto = b"\0".to_vec();
        let orig_tst1 = b"location has changed!\0".to_vec();
        let orig_msg2 = b"abnormal behavior!\0".to_vec();
        let orig_opts = b"\0".to_vec();
        let orig_text = b"echo hello world\0".to_vec();
        let orig_tst2 = b"shell has changed!\0".to_vec();

        // Encrypt
        let mut msg1 = orig_msg1.clone();
        let mut date = orig_date.clone();
        let mut shll = orig_shll.clone();
        let mut inlo = orig_inlo.clone();
        let mut xecc = orig_xecc.clone();
        let mut lsto = orig_lsto.clone();
        let mut tst1 = orig_tst1.clone();
        let chk1_plain = orig_tst1.clone();
        let mut msg2 = orig_msg2.clone();
        let mut rlax = vec![1u8]; // relax = true
        let mut opts = orig_opts.clone();
        let mut text = orig_text.clone();
        let mut tst2 = orig_tst2.clone();
        let chk2_plain = orig_tst2.clone();

        let mut rc4 = Rc4::new();
        rc4.reset();
        rc4.key(&pswd);
        rc4.arc4(&mut msg1);
        rc4.arc4(&mut date);
        rc4.arc4(&mut shll);
        rc4.arc4(&mut inlo);
        rc4.arc4(&mut xecc);
        rc4.arc4(&mut lsto);
        rc4.arc4(&mut tst1);

        let mut chk1 = chk1_plain;
        rc4.key(&chk1);
        rc4.arc4(&mut chk1);

        rc4.arc4(&mut msg2);
        rc4.arc4(&mut rlax);
        // rlax[0] was 1 (relax=true), so no key_with_file

        rc4.arc4(&mut opts);
        rc4.arc4(&mut text);
        rc4.arc4(&mut tst2);

        let mut chk2 = chk2_plain;
        rc4.key(&chk2);
        rc4.arc4(&mut chk2);

        // --- Pack into payload ---
        let payload = Payload {
            flags: FLAG_TRACEABLE,
            relax_was_zero: false,
            arrays: [
                pswd.clone(),
                msg1,
                date,
                shll,
                inlo,
                xecc,
                lsto,
                tst1,
                chk1,
                msg2,
                rlax,
                opts,
                text,
                tst2,
                chk2,
            ],
        };

        // Serialize and deserialize
        let mut buf = Vec::new();
        payload.serialize(&mut buf).unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();

        // --- Simulate runner decryption (same order as runner) ---
        let mut d_msg1 = restored.arrays[payload::IDX_MSG1].clone();
        let mut d_date = restored.arrays[payload::IDX_DATE].clone();
        let mut d_shll = restored.arrays[payload::IDX_SHLL].clone();
        let mut d_inlo = restored.arrays[payload::IDX_INLO].clone();
        let mut d_xecc = restored.arrays[payload::IDX_XECC].clone();
        let mut d_lsto = restored.arrays[payload::IDX_LSTO].clone();
        let mut d_tst1 = restored.arrays[payload::IDX_TST1].clone();
        let mut d_chk1 = restored.arrays[payload::IDX_CHK1].clone();
        let mut d_msg2 = restored.arrays[payload::IDX_MSG2].clone();
        let mut d_rlax = restored.arrays[payload::IDX_RLAX].clone();
        let mut d_opts = restored.arrays[payload::IDX_OPTS].clone();
        let mut d_text = restored.arrays[payload::IDX_TEXT].clone();
        let mut d_tst2 = restored.arrays[payload::IDX_TST2].clone();
        let mut d_chk2 = restored.arrays[payload::IDX_CHK2].clone();

        let mut rc4 = Rc4::new();
        rc4.reset();
        rc4.key(&restored.arrays[payload::IDX_PSWD]);

        rc4.arc4(&mut d_msg1);
        rc4.arc4(&mut d_date);
        rc4.arc4(&mut d_shll);
        rc4.arc4(&mut d_inlo);
        rc4.arc4(&mut d_xecc);
        rc4.arc4(&mut d_lsto);
        rc4.arc4(&mut d_tst1);

        rc4.key(&d_tst1);
        rc4.arc4(&mut d_chk1);

        rc4.arc4(&mut d_msg2);
        rc4.arc4(&mut d_rlax);
        // rlax[0] == 1 (relax=true), no key_with_file

        rc4.arc4(&mut d_opts);
        rc4.arc4(&mut d_text);
        rc4.arc4(&mut d_tst2);

        rc4.key(&d_tst2);
        rc4.arc4(&mut d_chk2);

        // Verify all fields decrypted correctly
        assert_eq!(d_msg1, orig_msg1, "msg1 mismatch");
        assert_eq!(d_date, orig_date, "date mismatch");
        assert_eq!(d_shll, orig_shll, "shll mismatch");
        assert_eq!(d_inlo, orig_inlo, "inlo mismatch");
        assert_eq!(d_xecc, orig_xecc, "xecc mismatch");
        assert_eq!(d_lsto, orig_lsto, "lsto mismatch");
        assert_eq!(d_tst1, orig_tst1, "tst1 mismatch");
        assert_eq!(d_msg2, orig_msg2, "msg2 mismatch");
        assert_eq!(d_opts, orig_opts, "opts mismatch");
        assert_eq!(d_text, orig_text, "text mismatch");
        assert_eq!(d_tst2, orig_tst2, "tst2 mismatch");

        // Integrity checks should pass
        assert_eq!(d_chk1, d_tst1, "integrity check 1 failed");
        assert_eq!(d_chk2, d_tst2, "integrity check 2 failed");
    }
}
