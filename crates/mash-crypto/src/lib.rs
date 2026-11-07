use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use mash_core::{MashError, Result};
use sha2::{Sha256, Sha384};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported TLS 1.3 AEAD cipher suites (`CRY-02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCipherSuite {
    /// `0x1301`: AES-128-GCM with SHA-256
    TlsAes128GcmSha256,
    /// `0x1302`: AES-256-GCM with SHA-384
    TlsAes256GcmSha384,
    /// `0x1303`: ChaCha20-Poly1305 with SHA-256
    TlsChacha20Poly1305Sha256,
}

impl TlsCipherSuite {
    pub const fn from_u16(code: u16) -> Option<Self> {
        match code {
            0x1301 => Some(Self::TlsAes128GcmSha256),
            0x1302 => Some(Self::TlsAes256GcmSha384),
            0x1303 => Some(Self::TlsChacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub const fn key_len(&self) -> usize {
        match self {
            Self::TlsAes128GcmSha256 => 16,
            Self::TlsAes256GcmSha384 | Self::TlsChacha20Poly1305Sha256 => 32,
        }
    }

    pub const fn iv_len(&self) -> usize {
        12
    }
}

/// Zeroized secret buffer (`REL-05`).
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}

/// Per-ClientRandom secrets parsed from an NSS `SSLKEYLOGFILE` or pcapng `DSB` (`CRY-01`).
#[derive(Debug, Clone, Default)]
pub struct SessionSecrets {
    pub master_secret: Option<SecretBytes>,
    pub client_handshake_traffic_secret: Option<SecretBytes>,
    pub server_handshake_traffic_secret: Option<SecretBytes>,
    pub client_traffic_secret_0: Option<SecretBytes>,
    pub server_traffic_secret_0: Option<SecretBytes>,
    pub early_traffic_secret: Option<SecretBytes>,
}

/// Store of TLS session secrets indexed by 32-byte `ClientRandom` (`CRY-01`).
#[derive(Debug, Clone, Default)]
pub struct TlsKeyStore {
    sessions: HashMap<[u8; 32], SessionSecrets>,
}

impl TlsKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn get(&self, client_random: &[u8; 32]) -> Option<&SessionSecrets> {
        self.sessions.get(client_random)
    }

    /// Load an `SSLKEYLOGFILE` from disk.
    pub fn load_keylog_file(&mut self, path: impl AsRef<Path>) -> Result<usize> {
        let content = fs::read_to_string(path.as_ref())?;
        Ok(self.parse_keylog_str(&content))
    }

    /// Parse `SSLKEYLOGFILE` lines from a string or pcapng `DSB` payload. Returns the number of secret lines ingested.
    pub fn parse_keylog_str(&mut self, text: &str) -> usize {
        let mut count = 0usize;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            let (Some(label), Some(cr_hex), Some(sec_hex)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Some(cr_bytes) = decode_hex(cr_hex) else {
                continue;
            };
            if cr_bytes.len() != 32 {
                continue;
            }
            let Some(sec_bytes) = decode_hex(sec_hex) else {
                continue;
            };
            let mut cr = [0u8; 32];
            cr.copy_from_slice(&cr_bytes);
            let entry = self.sessions.entry(cr).or_default();
            let secret = SecretBytes(sec_bytes);

            match label {
                "CLIENT_RANDOM" => entry.master_secret = Some(secret),
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
                    entry.client_handshake_traffic_secret = Some(secret)
                }
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                    entry.server_handshake_traffic_secret = Some(secret)
                }
                "CLIENT_TRAFFIC_SECRET_0" => entry.client_traffic_secret_0 = Some(secret),
                "SERVER_TRAFFIC_SECRET_0" => entry.server_traffic_secret_0 = Some(secret),
                "EARLY_TRAFFIC_SECRET" => entry.early_traffic_secret = Some(secret),
                _ => continue,
            }
            count += 1;
        }
        count
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

/// RFC 8446 Section 7.1 `HKDF-Expand-Label(Secret, Label, Context, Length)`.
pub fn hkdf_expand_label(
    prk: &[u8],
    use_sha384: bool,
    label: &str,
    context: &[u8],
    out_len: usize,
) -> Result<Vec<u8>> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full_label.len() + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut okm = vec![0u8; out_len];
    if use_sha384 {
        let hk = Hkdf::<Sha384>::from_prk(prk)
            .map_err(|e| MashError::Crypto(format!("Invalid SHA-384 PRK length: {e}")))?;
        hk.expand(&info, &mut okm)
            .map_err(|e| MashError::Crypto(format!("HKDF-Expand-Label (SHA-384) failed: {e}")))?;
    } else {
        let hk = Hkdf::<Sha256>::from_prk(prk)
            .map_err(|e| MashError::Crypto(format!("Invalid SHA-256 PRK length: {e}")))?;
        hk.expand(&info, &mut okm)
            .map_err(|e| MashError::Crypto(format!("HKDF-Expand-Label (SHA-256) failed: {e}")))?;
    }
    Ok(okm)
}

/// Derived directional TLS 1.3 AEAD key and 12-byte IV (`CRY-02`, `REL-05`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Tls13TrafficKeys {
    #[zeroize(skip)]
    pub suite: TlsCipherSuite,
    pub key: Vec<u8>,
    pub iv: [u8; 12],
}

impl fmt::Debug for Tls13TrafficKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13TrafficKeys")
            .field("suite", &self.suite)
            .field("key", &"[REDACTED]")
            .field("iv", &"[REDACTED]")
            .finish()
    }
}

impl Tls13TrafficKeys {
    /// Derive `key` and `iv` from a TLS 1.3 traffic secret per RFC 8446 Section 7.3.
    pub fn from_traffic_secret(suite: TlsCipherSuite, traffic_secret: &[u8]) -> Result<Self> {
        let use_sha384 = suite == TlsCipherSuite::TlsAes256GcmSha384;
        let key = hkdf_expand_label(traffic_secret, use_sha384, "key", &[], suite.key_len())?;
        let iv_vec = hkdf_expand_label(traffic_secret, use_sha384, "iv", &[], 12)?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        Ok(Self { suite, key, iv })
    }

    /// Compute the 12-byte per-record nonce (`iv XOR seq_num`).
    pub fn nonce_for_seq(&self, seq_num: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = seq_num.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    /// Decrypt a TLS 1.3 `TLSCiphertext` record (`record_header` = 5 bytes `[23, 0x03, 0x03, len_hi, len_lo]`, `ciphertext` = body including 16-byte tag).
    /// Returns `(inner_content_type, plaintext_without_padding)`.
    pub fn decrypt_record(
        &self,
        seq_num: u64,
        record_header: [u8; 5],
        ciphertext: &[u8],
    ) -> Result<(u8, Vec<u8>)> {
        let nonce_bytes = self.nonce_for_seq(seq_num);
        let payload = Payload {
            msg: ciphertext,
            aad: &record_header,
        };

        let mut decrypted = match self.suite {
            TlsCipherSuite::TlsAes128GcmSha256 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|e| MashError::Crypto(format!("AES-128-GCM init error: {e}")))?;
                cipher
                    .decrypt(AesNonce::from_slice(&nonce_bytes), payload)
                    .map_err(|_| MashError::Crypto("AES-128-GCM tag verification failed".to_string()))?
            }
            TlsCipherSuite::TlsAes256GcmSha384 => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|e| MashError::Crypto(format!("AES-256-GCM init error: {e}")))?;
                cipher
                    .decrypt(AesNonce::from_slice(&nonce_bytes), payload)
                    .map_err(|_| MashError::Crypto("AES-256-GCM tag verification failed".to_string()))?
            }
            TlsCipherSuite::TlsChacha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|e| MashError::Crypto(format!("ChaCha20-Poly1305 init error: {e}")))?;
                cipher
                    .decrypt(ChaChaNonce::from_slice(&nonce_bytes), payload)
                    .map_err(|_| {
                        MashError::Crypto("ChaCha20-Poly1305 tag verification failed".to_string())
                    })?
            }
        };

        // Strip trailing zero padding and extract TLS 1.3 inner ContentType byte
        while decrypted.last() == Some(&0) {
            decrypted.pop();
        }
        let inner_content_type = decrypted.pop().ok_or_else(|| {
            MashError::Crypto("Decrypted TLS 1.3 inner plaintext is empty".to_string())
        })?;
        Ok((inner_content_type, decrypted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;

    #[test]
    fn keylog_parser_and_tls13_record_decryption_roundtrip() {
        let mut store = TlsKeyStore::new();
        let cr_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let secret_hex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
        let log_line = format!("CLIENT_TRAFFIC_SECRET_0 {cr_hex} {secret_hex}\n");
        assert_eq!(store.parse_keylog_str(&log_line), 1);

        let cr_vec = decode_hex(cr_hex).unwrap();
        let mut cr = [0u8; 32];
        cr.copy_from_slice(&cr_vec);
        let sess = store.get(&cr).unwrap();
        let traffic_secret = &sess.client_traffic_secret_0.as_ref().unwrap().0;

        let keys = Tls13TrafficKeys::from_traffic_secret(
            TlsCipherSuite::TlsAes128GcmSha256,
            traffic_secret,
        )
        .unwrap();

        // Encrypt a synthetic TLS 1.3 Application Data record ("GET / HTTP/1.1\r\n\r\n" + inner type 23)
        let mut inner_plain = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        inner_plain.push(23); // inner content type = ApplicationData (23)
        let cipher_len = (inner_plain.len() + 16) as u16;
        let hdr = [23, 0x03, 0x03, (cipher_len >> 8) as u8, cipher_len as u8];
        let nonce = keys.nonce_for_seq(0);
        let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
        let ciphertext = cipher
            .encrypt(
                AesNonce::from_slice(&nonce),
                Payload {
                    msg: &inner_plain,
                    aad: &hdr,
                },
            )
            .unwrap();

        // Now decrypt via Tls13TrafficKeys::decrypt_record
        let (ct, plain) = keys.decrypt_record(0, hdr, &ciphertext).unwrap();
        assert_eq!(ct, 23);
        assert_eq!(plain, b"GET / HTTP/1.1\r\n\r\n");

        // Ensure Debug redacts secrets (REL-05)
        let dbg = format!("{keys:?}");
        assert!(dbg.contains("REDACTED"));
    }
}

