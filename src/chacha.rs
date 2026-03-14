use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Encrypt data with ChaCha20-Poly1305 (AEAD).
/// Returns (ciphertext_with_tag, nonce).
pub fn chacha_encrypt(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), String> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data with ChaCha20-Poly1305 (AEAD).
pub fn chacha_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("ChaCha20-Poly1305 decryption failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, World! This is a secret script.";

        let (ciphertext, nonce) = chacha_encrypt(plaintext, &key).unwrap();
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = chacha_decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_chacha_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"secret data";

        let (ciphertext, nonce) = chacha_encrypt(plaintext, &key).unwrap();
        assert!(chacha_decrypt(&ciphertext, &wrong_key, &nonce).is_err());
    }

    #[test]
    fn test_chacha_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret data";

        let (mut ciphertext, nonce) = chacha_encrypt(plaintext, &key).unwrap();
        ciphertext[0] ^= 0xFF;
        assert!(chacha_decrypt(&ciphertext, &key, &nonce).is_err());
    }

    #[test]
    fn test_chacha_empty_data() {
        let key = [0x42u8; 32];
        let (ciphertext, nonce) = chacha_encrypt(b"", &key).unwrap();
        let decrypted = chacha_decrypt(&ciphertext, &key, &nonce).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_chacha_large_data() {
        let key = [0x42u8; 32];
        let plaintext = vec![0xAB; 65536];
        let (ciphertext, nonce) = chacha_encrypt(&plaintext, &key).unwrap();
        let decrypted = chacha_decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
