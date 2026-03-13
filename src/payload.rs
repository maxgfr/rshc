use std::io::{self, Read, Seek, SeekFrom, Write};

pub const MAGIC: &[u8; 16] = b"RSHC_PAYLOAD_V1\0";
pub const NUM_ARRAYS: u16 = 15;

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

// Flag bits
pub const FLAG_SETUID: u8 = 0x01;
pub const FLAG_DEBUGEXEC: u8 = 0x02;
pub const FLAG_TRACEABLE: u8 = 0x04;
pub const FLAG_HARDENING: u8 = 0x08;
pub const FLAG_BUSYBOX: u8 = 0x10;
pub const FLAG_MMAP2: u8 = 0x20;

pub struct Payload {
    pub flags: u8,
    pub relax_was_zero: bool,
    pub arrays: [Vec<u8>; 15],
}

impl Payload {
    /// Serialize payload to a writer.
    /// Format: magic(16) + flags(1) + relax_was_zero(1) + num_arrays(2 LE)
    ///       + array_sizes(15 * 4 LE) + array_data + payload_size(8 LE)
    pub fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = Vec::new();

        buf.extend_from_slice(MAGIC);
        buf.push(self.flags);
        buf.push(u8::from(self.relax_was_zero));
        buf.extend_from_slice(&NUM_ARRAYS.to_le_bytes());

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
    pub fn deserialize<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 16];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
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

        let mut sizes = [0u32; 15];
        for size in &mut sizes {
            let mut sz_buf = [0u8; 4];
            r.read_exact(&mut sz_buf)?;
            *size = u32::from_le_bytes(sz_buf);
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
        let mut arrays: [Vec<u8>; 15] = Default::default();
        arrays[IDX_PSWD] = vec![1, 2, 3, 4];
        arrays[IDX_MSG1] = b"has expired!\n\0".to_vec();
        arrays[IDX_DATE] = b"\0".to_vec();
        arrays[IDX_SHLL] = b"/bin/sh\0".to_vec();
        arrays[IDX_INLO] = b"-c\0".to_vec();
        arrays[IDX_XECC] = b"exec '%s' \"$@\"\0".to_vec();
        arrays[IDX_LSTO] = b"\0".to_vec();
        arrays[IDX_TST1] = b"location has changed!\0".to_vec();
        arrays[IDX_CHK1] = b"location has changed!\0".to_vec();
        arrays[IDX_MSG2] = b"abnormal behavior!\0".to_vec();
        arrays[IDX_RLAX] = vec![0];
        arrays[IDX_OPTS] = b"\0".to_vec();
        arrays[IDX_TEXT] = b"echo hello\0".to_vec();
        arrays[IDX_TST2] = b"shell has changed!\0".to_vec();
        arrays[IDX_CHK2] = b"shell has changed!\0".to_vec();

        Payload {
            flags: FLAG_TRACEABLE,
            relax_was_zero: true,
            arrays,
        }
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
        // Simulate: [junk runner binary data] + [serialized payload]
        let payload = make_test_payload();
        let mut exe_data = vec![0xDE, 0xAD, 0xBE, 0xEF]; // fake binary prefix
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
        let buf = vec![0u8; 100];
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
        let mut arrays: [Vec<u8>; 15] = Default::default();
        // Simulate a large script (64KB)
        arrays[IDX_PSWD] = vec![0xAB; 256];
        arrays[IDX_TEXT] = vec![0x42; 65536];
        arrays[IDX_SHLL] = b"/bin/bash\0".to_vec();

        let payload = Payload {
            flags: 0xFF,
            relax_was_zero: false,
            arrays,
        };

        let mut buf = Vec::new();
        payload.serialize(&mut buf).unwrap();
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

        // Last 8 bytes should encode the total payload size
        let len = buf.len();
        let size_bytes: [u8; 8] = buf[len - 8..].try_into().unwrap();
        let encoded_size = u64::from_le_bytes(size_bytes);
        assert_eq!(encoded_size as usize, len);
    }

    #[test]
    fn test_empty_arrays() {
        let arrays: [Vec<u8>; 15] = Default::default();
        let payload = Payload {
            flags: 0,
            relax_was_zero: false,
            arrays,
        };

        let mut buf = Vec::new();
        payload.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let restored = Payload::deserialize(&mut cursor).unwrap();
        for i in 0..15 {
            assert!(restored.arrays[i].is_empty());
        }
    }
}
