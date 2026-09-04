use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::Zeroize;

/// Encrypt data with AES-256-GCM.
/// Returns (ciphertext_with_tag, nonce).
pub fn aes_encrypt(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data with AES-256-GCM.
pub fn aes_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-256-GCM decryption failed: {}", e))
}

/// Zero out a key securely.
pub fn zero_key(key: &mut [u8; 32]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, World! This is a secret script.";

        let (ciphertext, nonce) = aes_encrypt(plaintext, &key).unwrap();
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = aes_decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"secret data";

        let (ciphertext, nonce) = aes_encrypt(plaintext, &key).unwrap();
        let result = aes_decrypt(&ciphertext, &wrong_key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret data";

        let (ciphertext, _nonce) = aes_encrypt(plaintext, &key).unwrap();
        let wrong_nonce = [0xFF; 12];
        let result = aes_decrypt(&ciphertext, &key, &wrong_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret data";

        let (mut ciphertext, nonce) = aes_encrypt(plaintext, &key).unwrap();
        ciphertext[0] ^= 0xFF; // tamper
        let result = aes_decrypt(&ciphertext, &key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_empty_data() {
        let key = [0x42u8; 32];
        let plaintext = b"";

        let (ciphertext, nonce) = aes_encrypt(plaintext, &key).unwrap();
        let decrypted = aes_decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes_large_data() {
        let key = [0x42u8; 32];
        let plaintext = vec![0xAB; 65536];

        let (ciphertext, nonce) = aes_encrypt(&plaintext, &key).unwrap();
        let decrypted = aes_decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_zero_key() {
        let mut key = [0x42u8; 32];
        zero_key(&mut key);
        assert_eq!(key, [0u8; 32]);
    }
}
