use std::io::{self, Read, Seek, SeekFrom, Write};

pub const MAGIC: &[u8; 16] = b"RSHC_PAYLOAD_V2\0";
pub const MAGIC_V1: &[u8; 16] = b"RSHC_PAYLOAD_V1\0";
pub const NUM_ARRAYS: u16 = 15;

/// Maximum allowed size per array (10 MB) to prevent OOM from malformed payloads.
pub const MAX_ARRAY_SIZE: u32 = 10_000_000;

// Array indices (same order as codegen encryption)
pub const IDX_PSWD: usize = 0;
pub const IDX_MSG1: usize = 1;
pub const IDX_DATE: usize = 2;
pub const IDX_SHLL: usize = 3;
pub const IDX_INLO: usize = 4;
pub const IDX_XECC: usize = 5;
pub const IDX_LSTO: usize = 6;
pub const IDX_TST1: usize = 7;
pub const IDX_CHK1: usize = 8;
pub const IDX_MSG2: usize = 9;
pub const IDX_RLAX: usize = 10;
pub const IDX_OPTS: usize = 11;
pub const IDX_TEXT: usize = 12;
pub const IDX_TST2: usize = 13;
pub const IDX_CHK2: usize = 14;

// Flag bits (original)
pub const FLAG_SETUID: u8 = 0x01;
pub const FLAG_DEBUGEXEC: u8 = 0x02;
pub const FLAG_TRACEABLE: u8 = 0x04;
pub const FLAG_HARDENING: u8 = 0x08;
pub const FLAG_BUSYBOX: u8 = 0x10;
pub const FLAG_MMAP2: u8 = 0x20;

// Extended flag bits (V2)
pub const FLAG_EXT_AES: u8 = 0x01;
pub const FLAG_EXT_PASSWORD: u8 = 0x02;
pub const FLAG_EXT_COMPRESSED: u8 = 0x04;
pub const FLAG_EXT_STDIN_MODE: u8 = 0x08;
pub const FLAG_EXT_CHACHA: u8 = 0x10;
pub const FLAG_EXT_NO_NETWORK: u8 = 0x20;
pub const FLAG_EXT_BIND_HOST: u8 = 0x40;

#[derive(Default)]
pub struct Payload {
    pub flags: u8,
    pub relax_was_zero: bool,
    pub arrays: [Vec<u8>; 15],
    // V2 extended fields
    pub ext_flags: u8,
    pub password_salt: [u8; 32],
    pub password_hash: [u8; 32],
    pub aes_nonce: [u8; 12],
    pub max_runs: u32,
    pub integrity_hash: [u8; 32],
}

impl Payload {
    /// Serialize payload to a writer.
    /// V2 Format: magic(16) + flags(1) + relax_was_zero(1) + num_arrays(2 LE)
    ///          + ext_flags(1) + password_salt(32) + password_hash(32)
    ///          + aes_nonce(12) + max_runs(4 LE) + integrity_hash(32)
    ///          + array_sizes(15 * 4 LE) + array_data + payload_size(8 LE)
    pub fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = Vec::new();

        buf.extend_from_slice(MAGIC);
        buf.push(self.flags);
        buf.push(u8::from(self.relax_was_zero));
        buf.extend_from_slice(&NUM_ARRAYS.to_le_bytes());

        // V2 extended header
        buf.push(self.ext_flags);
        buf.extend_from_slice(&self.password_salt);
        buf.extend_from_slice(&self.password_hash);
        buf.extend_from_slice(&self.aes_nonce);
        buf.extend_from_slice(&self.max_runs.to_le_bytes());
        buf.extend_from_slice(&self.integrity_hash);

        for arr in &self.arrays {
            buf.extend_from_slice(&(arr.len() as u32).to_le_bytes());
        }
        for arr in &self.arrays {
            buf.extend_from_slice(arr);
        }

        let total_size = buf.len() as u64 + 8;
        buf.extend_from_slice(&total_size.to_le_bytes());

        w.write_all(&buf)
    }

    /// Deserialize payload from a reader positioned at the start of the payload.
    /// Supports both V1 and V2 formats.
    pub fn deserialize<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 16];
        r.read_exact(&mut magic)?;

        let is_v2 = &magic == MAGIC;
        let is_v1 = &magic == MAGIC_V1;

        if !is_v2 && !is_v1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid payload magic",
            ));
        }

        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        let flags = byte[0];

        r.read_exact(&mut byte)?;
        let relax_was_zero = byte[0] != 0;

        let mut na_buf = [0u8; 2];
        r.read_exact(&mut na_buf)?;
        let num_arrays = u16::from_le_bytes(na_buf);
        if num_arrays != NUM_ARRAYS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected number of arrays",
            ));
        }

        // V2 extended header
        let mut ext_flags = 0u8;
        let mut password_salt = [0u8; 32];
        let mut password_hash = [0u8; 32];
        let mut aes_nonce = [0u8; 12];
        let mut max_runs = 0u32;
        let mut integrity_hash = [0u8; 32];

        if is_v2 {
            r.read_exact(&mut byte)?;
            ext_flags = byte[0];
            r.read_exact(&mut password_salt)?;
            r.read_exact(&mut password_hash)?;
            r.read_exact(&mut aes_nonce)?;
            let mut mr_buf = [0u8; 4];
            r.read_exact(&mut mr_buf)?;
            max_runs = u32::from_le_bytes(mr_buf);
            r.read_exact(&mut integrity_hash)?;
        }

        let mut sizes = [0u32; 15];
        for size in &mut sizes {
            let mut sz_buf = [0u8; 4];
            r.read_exact(&mut sz_buf)?;
            *size = u32::from_le_bytes(sz_buf);
            if *size > MAX_ARRAY_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("array size {} exceeds maximum {}", *size, MAX_ARRAY_SIZE),
                ));
            }
        }

        let mut arrays: [Vec<u8>; 15] = Default::default();
        for (i, arr) in arrays.iter_mut().enumerate() {
            let mut data = vec![0u8; sizes[i] as usize];
            r.read_exact(&mut data)?;
            *arr = data;
        }

        Ok(Payload {
            flags,
            relax_was_zero,
            arrays,
            ext_flags,
            password_salt,
            password_hash,
            aes_nonce,
            max_runs,
            integrity_hash,
        })
    }

    /// Read payload from the end of an executable (trailer pattern).
    /// The last 8 bytes encode the total payload size.
    pub fn read_from_exe<R: Read + Seek>(r: &mut R) -> io::Result<Self> {
        r.seek(SeekFrom::End(-8))?;
        let mut size_buf = [0u8; 8];
        r.read_exact(&mut size_buf)?;
        let payload_size = u64::from_le_bytes(size_buf);

        r.seek(SeekFrom::End(-(payload_size as i64)))?;
        Self::deserialize(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_test_payload() -> Payload {
        let mut p = Payload::default();
        p.flags = FLAG_TRACEABLE;
        p.relax_was_zero = true;
        p.arrays[IDX_PSWD] = vec![1, 2, 3, 4];
        p.arrays[IDX_MSG1] = b"has expired!\n\0".to_vec();
        p.arrays[IDX_DATE] = b"\0".to_vec();
        p.arrays[IDX_SHLL] = b"/bin/sh\0".to_vec();
        p.arrays[IDX_INLO] = b"-c\0".to_vec();
        p.arrays[IDX_XECC] = b"exec '%s' \"$@\"\0".to_vec();
        p.arrays[IDX_LSTO] = b"\0".to_vec();
        p.arrays[IDX_TST1] = b"location has changed!\0".to_vec();
        p.arrays[IDX_CHK1] = b"location has changed!\0".to_vec();
        p.arrays[IDX_MSG2] = b"abnormal behavior!\0".to_vec();
        p.arrays[IDX_RLAX] = vec![0];
        p.arrays[IDX_OPTS] = b"\0".to_vec();
        p.arrays[IDX_TEXT] = b"echo hello\0".to_vec();
        p.arrays[IDX_TST2] = b"shell has changed!\0".to_vec();
        p.arrays[IDX_CHK2] = b"shell has changed!\0".to_vec();
        p
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let payload = make_test_payload();
        let mut buf = Vec::new();
        payload.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();

        assert_eq!(restored.flags, payload.flags);
        assert_eq!(restored.relax_was_zero, payload.relax_was_zero);
        for i in 0..15 {
            assert_eq!(
                restored.arrays[i], payload.arrays[i],
                "array {} mismatch",
                i
            );
        }
    }

    #[test]
    fn test_read_from_exe_trailer() {
        let payload = make_test_payload();
        let mut exe_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        payload.serialize(&mut exe_data).unwrap();

        let mut cursor = Cursor::new(&exe_data);
        let restored = Payload::read_from_exe(&mut cursor).unwrap();

        assert_eq!(restored.flags, payload.flags);
        assert_eq!(restored.relax_was_zero, payload.relax_was_zero);
        for i in 0..15 {
            assert_eq!(
                restored.arrays[i], payload.arrays[i],
                "array {} mismatch",
                i
            );
        }
    }

    #[test]
    fn test_invalid_magic() {
        let buf = vec![0u8; 200];
        let mut cursor = Cursor::new(&buf[..]);
        assert!(Payload::deserialize(&mut cursor).is_err());
    }

    #[test]
    fn test_flags_encoding() {
        let mut payload = make_test_payload();
        payload.flags = FLAG_SETUID | FLAG_HARDENING | FLAG_TRACEABLE;

        let mut buf = Vec::new();
        payload.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();
        assert!(restored.flags & FLAG_SETUID != 0);
        assert!(restored.flags & FLAG_HARDENING != 0);
        assert!(restored.flags & FLAG_TRACEABLE != 0);
        assert!(restored.flags & FLAG_DEBUGEXEC == 0);
        assert!(restored.flags & FLAG_BUSYBOX == 0);
    }

    #[test]
    fn test_large_payload() {
        let mut p = Payload::default();
        p.flags = 0xFF;
        p.arrays[IDX_PSWD] = vec![0xAB; 256];
        p.arrays[IDX_TEXT] = vec![0x42; 65536];
        p.arrays[IDX_SHLL] = b"/bin/bash\0".to_vec();

        let mut buf = Vec::new();
        p.serialize(&mut buf).unwrap();
        assert!(buf.len() > 65536);

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();
        assert_eq!(restored.arrays[IDX_TEXT].len(), 65536);
        assert_eq!(restored.arrays[IDX_PSWD].len(), 256);
    }

    #[test]
    fn test_payload_size_trailer() {
        let payload = make_test_payload();
        let mut buf = Vec::new();
        payload.serialize(&mut buf).unwrap();

        let len = buf.len();
        let size_bytes: [u8; 8] = buf[len - 8..].try_into().unwrap();
        let encoded_size = u64::from_le_bytes(size_bytes);
        assert_eq!(encoded_size as usize, len);
    }

    #[test]
    fn test_empty_arrays() {
        let p = Payload::default();
        let mut buf = Vec::new();
        p.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();
        for i in 0..15 {
            assert!(restored.arrays[i].is_empty());
        }
    }

    #[test]
    fn test_v2_extended_fields_roundtrip() {
        let mut payload = make_test_payload();
        payload.ext_flags = FLAG_EXT_AES | FLAG_EXT_COMPRESSED | FLAG_EXT_PASSWORD;
        payload.password_salt = [0xAA; 32];
        payload.password_hash = [0xBB; 32];
        payload.aes_nonce = [0xCC; 12];
        payload.max_runs = 42;
        payload.integrity_hash = [0xDD; 32];

        let mut buf = Vec::new();
        payload.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();

        assert_eq!(restored.ext_flags, payload.ext_flags);
        assert_eq!(restored.password_salt, payload.password_salt);
        assert_eq!(restored.password_hash, payload.password_hash);
        assert_eq!(restored.aes_nonce, payload.aes_nonce);
        assert_eq!(restored.max_runs, 42);
        assert_eq!(restored.integrity_hash, payload.integrity_hash);
    }

    #[test]
    fn test_v2_ext_flags() {
        let mut p = make_test_payload();
        p.ext_flags = FLAG_EXT_AES | FLAG_EXT_STDIN_MODE;

        let mut buf = Vec::new();
        p.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();
        assert!(restored.ext_flags & FLAG_EXT_AES != 0);
        assert!(restored.ext_flags & FLAG_EXT_STDIN_MODE != 0);
        assert!(restored.ext_flags & FLAG_EXT_PASSWORD == 0);
        assert!(restored.ext_flags & FLAG_EXT_COMPRESSED == 0);
    }

    #[test]
    fn test_max_runs_roundtrip() {
        let mut p = make_test_payload();
        p.max_runs = 999;

        let mut buf = Vec::new();
        p.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();
        assert_eq!(restored.max_runs, 999);
    }

    #[test]
    fn test_oversized_array_rejected() {
        // Craft a payload with an array size exceeding MAX_ARRAY_SIZE
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC); // magic
        buf.push(0); // flags
        buf.push(0); // relax_was_zero
        buf.extend_from_slice(&NUM_ARRAYS.to_le_bytes()); // num_arrays
        buf.push(0); // ext_flags
        buf.extend_from_slice(&[0u8; 32]); // password_salt
        buf.extend_from_slice(&[0u8; 32]); // password_hash
        buf.extend_from_slice(&[0u8; 12]); // aes_nonce
        buf.extend_from_slice(&0u32.to_le_bytes()); // max_runs
        buf.extend_from_slice(&[0u8; 32]); // integrity_hash
                                           // First array size = MAX_ARRAY_SIZE + 1 (too large)
        let bad_size = MAX_ARRAY_SIZE + 1;
        buf.extend_from_slice(&bad_size.to_le_bytes());
        // Remaining 14 array sizes = 0
        for _ in 0..14 {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        let mut cursor = Cursor::new(&buf);
        let result = Payload::deserialize(&mut cursor);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "expected 'exceeds maximum' error, got: {}",
            err
        );
    }

    #[test]
    fn test_v1_payload_backward_compat() {
        // Craft a V1 payload manually and verify it can be deserialized
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC_V1); // V1 magic
        buf.push(FLAG_TRACEABLE); // flags
        buf.push(1); // relax_was_zero = true
        buf.extend_from_slice(&NUM_ARRAYS.to_le_bytes());
        // Array sizes (all small)
        let test_arrays: [&[u8]; 15] = [
            &[1, 2, 3],   // pswd
            b"msg1\0",    // msg1
            b"\0",        // date
            b"/bin/sh\0", // shll
            b"-c\0",      // inlo
            b"exec\0",    // xecc
            b"\0",        // lsto
            b"tst1\0",    // tst1
            b"chk1\0",    // chk1
            b"msg2\0",    // msg2
            &[0],         // rlax
            b"\0",        // opts
            b"echo hi\0", // text
            b"tst2\0",    // tst2
            b"chk2\0",    // chk2
        ];
        for arr in &test_arrays {
            buf.extend_from_slice(&(arr.len() as u32).to_le_bytes());
        }
        for arr in &test_arrays {
            buf.extend_from_slice(arr);
        }
        let total = buf.len() as u64 + 8;
        buf.extend_from_slice(&total.to_le_bytes());

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();

        assert_eq!(restored.flags, FLAG_TRACEABLE);
        assert!(restored.relax_was_zero);
        assert_eq!(restored.arrays[IDX_PSWD], &[1, 2, 3]);
        assert_eq!(restored.arrays[IDX_SHLL], b"/bin/sh\0");
        // V1 should have default extended fields
        assert_eq!(restored.ext_flags, 0);
        assert_eq!(restored.password_salt, [0u8; 32]);
        assert_eq!(restored.max_runs, 0);
    }
}
