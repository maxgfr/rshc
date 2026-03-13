pub struct Rc4 {
    stte: [u8; 256],
    indx: u8,
    jndx: u8,
    kndx: u8,
}

impl Rc4 {
    pub fn new() -> Self {
        let mut rc4 = Rc4 {
            stte: [0u8; 256],
            indx: 0,
            jndx: 0,
            kndx: 0,
        };
        rc4.reset();
        rc4
    }

    /// Reset arc4 state — identity permutation.
    /// Matches stte_0() in shc.c:912-918.
    pub fn reset(&mut self) {
        self.indx = 0;
        self.jndx = 0;
        self.kndx = 0;
        loop {
            self.stte[self.indx as usize] = self.indx;
            self.indx = self.indx.wrapping_add(1);
            if self.indx == 0 {
                break;
            }
        }
    }

    /// Key scheduling — can be called more than once.
    /// Matches key() in shc.c:923-937.
    pub fn key(&mut self, data: &[u8]) {
        let mut remaining = data.len() as i32;
        let mut ptr_offset: usize = 0;
        while remaining > 0 {
            loop {
                let tmp = self.stte[self.indx as usize];
                self.kndx = self.kndx.wrapping_add(tmp);
                self.kndx = self.kndx.wrapping_add(
                    data[ptr_offset + (self.indx as usize % remaining as usize)],
                );
                self.stte[self.indx as usize] = self.stte[self.kndx as usize];
                self.stte[self.kndx as usize] = tmp;
                self.indx = self.indx.wrapping_add(1);
                if self.indx == 0 {
                    break;
                }
            }
            ptr_offset += 256;
            remaining -= 256;
        }
    }

    /// XOR stream cipher.
    /// Matches arc4() in shc.c:942-956.
    pub fn arc4(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.indx = self.indx.wrapping_add(1);
            let tmp = self.stte[self.indx as usize];
            self.jndx = self.jndx.wrapping_add(tmp);
            self.stte[self.indx as usize] = self.stte[self.jndx as usize];
            self.stte[self.jndx as usize] = tmp;
            let t = tmp.wrapping_add(self.stte[self.indx as usize]);
            *byte ^= self.stte[t as usize];
        }
    }

    /// Key with file invariants — stat() the shell binary and use stable fields.
    /// Matches key_with_file() in shc.c:963-983.
    pub fn key_with_file(&mut self, path: &str) -> Result<(), std::io::Error> {
        use std::mem;

        let c_path = std::ffi::CString::new(path).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path")
        })?;

        unsafe {
            let mut statf: libc::stat = mem::zeroed();
            if libc::stat(c_path.as_ptr(), &mut statf) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let mut control: libc::stat = mem::zeroed();
            control.st_ino = statf.st_ino;
            control.st_dev = statf.st_dev;
            control.st_rdev = statf.st_rdev;
            control.st_uid = statf.st_uid;
            control.st_gid = statf.st_gid;
            control.st_size = statf.st_size;
            control.st_mtime = statf.st_mtime;
            control.st_ctime = statf.st_ctime;

            let control_bytes = std::slice::from_raw_parts(
                &control as *const libc::stat as *const u8,
                mem::size_of::<libc::stat>(),
            );
            self.key(control_bytes);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_encrypt_decrypt() {
        let mut rc4 = Rc4::new();
        rc4.reset();
        rc4.key(b"test key");

        let original = b"Hello, World!".to_vec();
        let mut data = original.clone();
        rc4.arc4(&mut data);
        assert_ne!(&data[..], &original[..]);

        // Decrypt with same key
        let mut rc4_dec = Rc4::new();
        rc4_dec.reset();
        rc4_dec.key(b"test key");
        rc4_dec.arc4(&mut data);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_reset_identity() {
        let rc4 = Rc4::new();
        for i in 0u8..=255 {
            assert_eq!(rc4.stte[i as usize], i);
        }
    }
}
