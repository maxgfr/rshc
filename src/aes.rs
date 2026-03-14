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

/// Derive a 256-bit AES key from a password and salt using SHA-256.
pub fn derive_key(password: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password);
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
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
    fn test_derive_key_deterministic() {
        let password = b"my_password";
        let salt = [0x11u8; 32];

        let key1 = derive_key(password, &salt);
        let key2 = derive_key(password, &salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"my_password";
        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];

        let key1 = derive_key(password, &salt1);
        let key2 = derive_key(password, &salt2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = [0x11u8; 32];
        let key1 = derive_key(b"password1", &salt);
        let key2 = derive_key(b"password2", &salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_zero_key() {
        let mut key = [0x42u8; 32];
        zero_key(&mut key);
        assert_eq!(key, [0u8; 32]);
    }
}
