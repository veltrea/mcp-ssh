use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use keyring::Entry;
use rand::RngCore;

pub struct SecurityManager {
    service_name: String,
}

impl SecurityManager {
    pub fn new(service: &str) -> Self {
        Self {
            service_name: service.to_string(),
        }
    }

    fn store_secret(&self, account: &str, secret: &str) -> Result<()> {
        let entry = Entry::new(&self.service_name, account)?;
        entry.set_password(secret)?;
        Ok(())
    }

    fn get_secret(&self, account: &str) -> Result<String> {
        let entry = Entry::new(&self.service_name, account)?;
        Ok(entry.get_password()?)
    }

    fn generate_new_master_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    pub fn get_or_create_master_key(&self) -> Result<[u8; 32]> {
        match self.get_secret("master_key") {
            Ok(hex_key) => {
                let mut key = [0u8; 32];
                hex::decode_to_slice(hex_key, &mut key).context("Failed to decode master key")?;
                Ok(key)
            }
            Err(e) => {
                if let Some(keyring::Error::NoEntry) = e.downcast_ref::<keyring::Error>() {
                    let key = self.generate_new_master_key();
                    self.store_secret("master_key", &hex::encode(key))?;
                    Ok(key)
                } else {
                    Err(e).context("Failed to retrieve master key from keyring")
                }
            }
        }
    }

    // Supports new format (nonce + ciphertext) and legacy fixed nonce format.
    pub fn decrypt(&self, key: &[u8; 32], b64_ciphertext: &str) -> Result<String> {
        let combined = base64::engine::general_purpose::STANDARD
            .decode(b64_ciphertext)
            .context("Failed to decode credential as base64")?;

        let cipher = Aes256Gcm::new(key.into());

        if combined.len() < 12 {
            let nonce = Nonce::from_slice(b"unique nonce");
            let plaintext = cipher
                .decrypt(nonce, combined.as_slice())
                .map_err(|e| anyhow!("Credential decryption failed (legacy format): {}", e))?;
            return String::from_utf8(plaintext).context("Credential is not valid UTF-8");
        }

        let (nonce_bytes, ciphertext_bytes) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        match cipher.decrypt(nonce, ciphertext_bytes) {
            Ok(plaintext) => String::from_utf8(plaintext).context("Credential is not valid UTF-8"),
            Err(_) => {
                let fixed_nonce = Nonce::from_slice(b"unique nonce");
                let plaintext = cipher
                    .decrypt(fixed_nonce, combined.as_slice())
                    .map_err(|e| anyhow!("Credential decryption failed (new+legacy): {}", e))?;
                String::from_utf8(plaintext).context("Credential is not valid UTF-8")
            }
        }
    }
}
