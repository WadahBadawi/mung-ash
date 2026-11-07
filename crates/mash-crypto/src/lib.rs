use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use mash_core::{Frame, LinkType, MashError, Result};
use sha2::{Sha256, Sha384};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

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

/// Supported TLS 1.2 AEAD cipher suites (`CRY-02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12CipherSuite {
    /// `0x009C`, `0xC02B`, `0xC02F`: AES-128-GCM with SHA-256
    Aes128GcmSha256,
    /// `0x009D`, `0xC02C`, `0xC030`: AES-256-GCM with SHA-384
    Aes256GcmSha384,
    /// `0xCCA8`, `0xCCA9`: ChaCha20-Poly1305 with SHA-256 (RFC 7905)
    Chacha20Poly1305Sha256,
}

impl Tls12CipherSuite {
    pub const fn from_u16(code: u16) -> Option<Self> {
        match code {
            0x009c | 0x009e | 0xc02b | 0xc02f => Some(Self::Aes128GcmSha256),
            0x009d | 0x009f | 0xc02c | 0xc030 => Some(Self::Aes256GcmSha384),
            0xcca8..=0xccaa => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub const fn key_len(&self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    pub const fn fixed_iv_len(&self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 => 4,
            Self::Chacha20Poly1305Sha256 => 12,
        }
    }

    pub const fn use_sha384(&self) -> bool {
        matches!(self, Self::Aes256GcmSha384)
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

/// RFC 5246 Section 5 TLS 1.2 Pseudo-Random Function `PRF(secret, label, seed)`.
pub fn tls12_prf(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    use_sha384: bool,
    out_len: usize,
) -> Result<Vec<u8>> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut out = Vec::with_capacity(out_len);
    if use_sha384 {
        let mut a = {
            let mut mac = <HmacSha384 as Mac>::new_from_slice(secret)
                .map_err(|e| MashError::Crypto(format!("HMAC-SHA384 init failed: {e}")))?;
            mac.update(&label_seed);
            mac.finalize().into_bytes().to_vec()
        };
        while out.len() < out_len {
            let mut mac = <HmacSha384 as Mac>::new_from_slice(secret)
                .map_err(|e| MashError::Crypto(format!("HMAC-SHA384 init failed: {e}")))?;
            mac.update(&a);
            mac.update(&label_seed);
            let block = mac.finalize().into_bytes();
            let take = (out_len - out.len()).min(block.len());
            out.extend_from_slice(&block[..take]);

            let mut next_a = <HmacSha384 as Mac>::new_from_slice(secret)
                .map_err(|e| MashError::Crypto(format!("HMAC-SHA384 init failed: {e}")))?;
            next_a.update(&a);
            a = next_a.finalize().into_bytes().to_vec();
        }
    } else {
        let mut a = {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
                .map_err(|e| MashError::Crypto(format!("HMAC-SHA256 init failed: {e}")))?;
            mac.update(&label_seed);
            mac.finalize().into_bytes().to_vec()
        };
        while out.len() < out_len {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
                .map_err(|e| MashError::Crypto(format!("HMAC-SHA256 init failed: {e}")))?;
            mac.update(&a);
            mac.update(&label_seed);
            let block = mac.finalize().into_bytes();
            let take = (out_len - out.len()).min(block.len());
            out.extend_from_slice(&block[..take]);

            let mut next_a = <HmacSha256 as Mac>::new_from_slice(secret)
                .map_err(|e| MashError::Crypto(format!("HMAC-SHA256 init failed: {e}")))?;
            next_a.update(&a);
            a = next_a.finalize().into_bytes().to_vec();
        }
    }
    Ok(out)
}

/// Derived TLS 1.2 bidirectional AEAD keys and implicit IVs (`CRY-02`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Tls12TrafficKeys {
    #[zeroize(skip)]
    pub suite: Tls12CipherSuite,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl fmt::Debug for Tls12TrafficKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls12TrafficKeys")
            .field("suite", &self.suite)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl Tls12TrafficKeys {
    /// Derive TLS 1.2 key block from `master_secret`, `client_random`, and `server_random` per RFC 5246 Section 6.3.
    pub fn from_master_secret(
        suite: Tls12CipherSuite,
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<Self> {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(server_random);
        seed[32..].copy_from_slice(client_random);

        let key_len = suite.key_len();
        let iv_len = suite.fixed_iv_len();
        let total = 2 * key_len + 2 * iv_len;
        let key_block = tls12_prf(
            master_secret,
            b"key expansion",
            &seed,
            suite.use_sha384(),
            total,
        )?;

        let client_write_key = key_block[0..key_len].to_vec();
        let server_write_key = key_block[key_len..2 * key_len].to_vec();
        let client_write_iv = key_block[2 * key_len..2 * key_len + iv_len].to_vec();
        let server_write_iv = key_block[2 * key_len + iv_len..total].to_vec();

        Ok(Self {
            suite,
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        })
    }

    /// Decrypt a TLS 1.2 AEAD record.
    /// For AES-GCM, `record_body` starts with an 8-byte explicit nonce followed by ciphertext + 16-byte tag.
    /// For ChaCha20-Poly1305 (RFC 7905), `record_body` is ciphertext + 16-byte tag with no explicit nonce.
    pub fn decrypt_record(
        &self,
        is_from_client: bool,
        seq_num: u64,
        content_type: u8,
        version: u16,
        record_body: &[u8],
    ) -> Result<Vec<u8>> {
        let (key, fixed_iv) = if is_from_client {
            (&self.client_write_key, &self.client_write_iv)
        } else {
            (&self.server_write_key, &self.server_write_iv)
        };

        match self.suite {
            Tls12CipherSuite::Aes128GcmSha256 | Tls12CipherSuite::Aes256GcmSha384 => {
                if record_body.len() < 8 + 16 {
                    return Err(MashError::Crypto(
                        "TLS 1.2 AES-GCM record too short".to_string(),
                    ));
                }
                let explicit_nonce = &record_body[..8];
                let ciphertext = &record_body[8..];
                let plain_len = (ciphertext.len() - 16) as u16;

                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(fixed_iv);
                nonce[4..].copy_from_slice(explicit_nonce);

                let mut aad = [0u8; 13];
                aad[..8].copy_from_slice(&seq_num.to_be_bytes());
                aad[8] = content_type;
                aad[9..11].copy_from_slice(&version.to_be_bytes());
                aad[11..13].copy_from_slice(&plain_len.to_be_bytes());

                let payload = Payload {
                    msg: ciphertext,
                    aad: &aad,
                };
                if self.suite == Tls12CipherSuite::Aes128GcmSha256 {
                    let cipher = Aes128Gcm::new_from_slice(key)
                        .map_err(|e| MashError::Crypto(format!("AES-128-GCM init error: {e}")))?;
                    cipher
                        .decrypt(AesNonce::from_slice(&nonce), payload)
                        .map_err(|_| {
                            MashError::Crypto("TLS 1.2 AES-128-GCM tag mismatch".to_string())
                        })
                } else {
                    let cipher = Aes256Gcm::new_from_slice(key)
                        .map_err(|e| MashError::Crypto(format!("AES-256-GCM init error: {e}")))?;
                    cipher
                        .decrypt(AesNonce::from_slice(&nonce), payload)
                        .map_err(|_| {
                            MashError::Crypto("TLS 1.2 AES-256-GCM tag mismatch".to_string())
                        })
                }
            }
            Tls12CipherSuite::Chacha20Poly1305Sha256 => {
                if record_body.len() < 16 {
                    return Err(MashError::Crypto(
                        "TLS 1.2 ChaCha20-Poly1305 record too short".to_string(),
                    ));
                }
                let plain_len = (record_body.len() - 16) as u16;
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(fixed_iv);
                let seq_bytes = seq_num.to_be_bytes();
                for i in 0..8 {
                    nonce[4 + i] ^= seq_bytes[i];
                }

                let mut aad = [0u8; 13];
                aad[..8].copy_from_slice(&seq_num.to_be_bytes());
                aad[8] = content_type;
                aad[9..11].copy_from_slice(&version.to_be_bytes());
                aad[11..13].copy_from_slice(&plain_len.to_be_bytes());

                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| MashError::Crypto(format!("ChaCha20-Poly1305 init error: {e}")))?;
                cipher
                    .decrypt(
                        ChaChaNonce::from_slice(&nonce),
                        Payload {
                            msg: record_body,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        MashError::Crypto("TLS 1.2 ChaCha20-Poly1305 tag mismatch".to_string())
                    })
            }
        }
    }
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

/// Decrypted TLS record output (`CRY-02`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedTlsRecord {
    pub record_index: usize,
    pub inner_content_type: u8,
    pub plaintext: Vec<u8>,
}

/// Stateful per-stream TLS handshake & record decryptor (`CRY-01`, `CRY-02`).
#[derive(Debug, Clone, Default)]
pub struct TlsStreamDecryptor {
    pub client_endpoint: Option<(String, u16)>,
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
    pub cipher_suite_code: Option<u16>,
    pub client_seq: u64,
    pub server_seq: u64,
    pub tls13_client_app_keys: Option<Tls13TrafficKeys>,
    pub tls13_server_app_keys: Option<Tls13TrafficKeys>,
    pub tls12_keys: Option<Tls12TrafficKeys>,
}

impl TlsStreamDecryptor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a TCP payload containing one or more TLS records, updating handshake parameters
    /// and returning any successfully decrypted `ApplicationData` records.
    pub fn process_tcp_payload(
        &mut self,
        src_addr: &str,
        src_port: u16,
        payload: &[u8],
        keystore: &TlsKeyStore,
    ) -> Vec<DecryptedTlsRecord> {
        let mut results = Vec::new();
        let mut offset = 0usize;
        let mut rec_idx = 0usize;

        while offset + 5 <= payload.len() {
            let content_type = payload[offset];
            let version = u16::from_be_bytes([payload[offset + 1], payload[offset + 2]]);
            let rec_len = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
            let Some(body) = payload.get(offset + 5..offset + 5 + rec_len) else {
                break;
            };
            let hdr: [u8; 5] = [
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
                payload[offset + 4],
            ];

            if content_type == 22 && body.len() >= 38 {
                let hs_type = body[0];
                // Handshake header: 1 byte type + 3 bytes length + 2 bytes version + 32 bytes random
                if hs_type == 1 {
                    // ClientHello
                    let mut cr = [0u8; 32];
                    cr.copy_from_slice(&body[6..38]);
                    self.client_random = Some(cr);
                    self.client_endpoint = Some((src_addr.to_string(), src_port));
                    self.try_derive_keys(keystore);
                } else if hs_type == 2 {
                    // ServerHello
                    let mut sr = [0u8; 32];
                    sr.copy_from_slice(&body[6..38]);
                    self.server_random = Some(sr);
                    if let Some(&sid_len) = body.get(38) {
                        let cs_off = 39 + sid_len as usize;
                        if let Some(cs_bytes) = body.get(cs_off..cs_off + 2) {
                            self.cipher_suite_code =
                                Some(u16::from_be_bytes([cs_bytes[0], cs_bytes[1]]));
                        }
                    }
                    self.try_derive_keys(keystore);
                }
            } else if content_type == 23 {
                let is_client = self
                    .client_endpoint
                    .as_ref()
                    .map(|(a, p)| a == src_addr && *p == src_port)
                    .unwrap_or(true);

                if is_client {
                    let seq = self.client_seq;
                    if let Some(keys) = &self.tls13_client_app_keys {
                        if let Ok((inner_ct, plain)) = keys.decrypt_record(seq, hdr, body) {
                            self.client_seq += 1;
                            results.push(DecryptedTlsRecord {
                                record_index: rec_idx,
                                inner_content_type: inner_ct,
                                plaintext: plain,
                            });
                        }
                    } else if let Some(keys12) = &self.tls12_keys {
                        if let Ok(plain) =
                            keys12.decrypt_record(true, seq, content_type, version, body)
                        {
                            self.client_seq += 1;
                            results.push(DecryptedTlsRecord {
                                record_index: rec_idx,
                                inner_content_type: 23,
                                plaintext: plain,
                            });
                        }
                    }
                } else {
                    let seq = self.server_seq;
                    if let Some(keys) = &self.tls13_server_app_keys {
                        if let Ok((inner_ct, plain)) = keys.decrypt_record(seq, hdr, body) {
                            self.server_seq += 1;
                            results.push(DecryptedTlsRecord {
                                record_index: rec_idx,
                                inner_content_type: inner_ct,
                                plaintext: plain,
                            });
                        }
                    } else if let Some(keys12) = &self.tls12_keys {
                        if let Ok(plain) =
                            keys12.decrypt_record(false, seq, content_type, version, body)
                        {
                            self.server_seq += 1;
                            results.push(DecryptedTlsRecord {
                                record_index: rec_idx,
                                inner_content_type: 23,
                                plaintext: plain,
                            });
                        }
                    }
                }
            }

            offset += 5 + rec_len;
            rec_idx += 1;
        }

        results
    }

    fn try_derive_keys(&mut self, keystore: &TlsKeyStore) {
        let Some(cr) = &self.client_random else {
            return;
        };
        let Some(secrets) = keystore.get(cr) else {
            return;
        };
        let cs_code = self.cipher_suite_code.unwrap_or(0x1301);

        if let Some(suite13) = TlsCipherSuite::from_u16(cs_code) {
            if self.tls13_client_app_keys.is_none() {
                if let Some(sec) = &secrets.client_traffic_secret_0 {
                    self.tls13_client_app_keys =
                        Tls13TrafficKeys::from_traffic_secret(suite13, &sec.0).ok();
                }
            }
            if self.tls13_server_app_keys.is_none() {
                if let Some(sec) = &secrets.server_traffic_secret_0 {
                    self.tls13_server_app_keys =
                        Tls13TrafficKeys::from_traffic_secret(suite13, &sec.0).ok();
                }
            }
        } else if let (Some(suite12), Some(sr), Some(ms)) = (
            Tls12CipherSuite::from_u16(cs_code),
            &self.server_random,
            &secrets.master_secret,
        ) {
            if self.tls12_keys.is_none() {
                self.tls12_keys =
                    Tls12TrafficKeys::from_master_secret(suite12, &ms.0, cr, sr).ok();
            }
        }
    }
}

/// Keyed packet anonymizer for scrubbing MACs, IPv4/IPv6 addresses, and L4 payloads (`CRY-03`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PcapAnonymizer {
    key: [u8; 32],
    #[zeroize(skip)]
    pub preserve_mac_oui: bool,
    #[zeroize(skip)]
    pub scrub_payload: bool,
}

impl PcapAnonymizer {
    pub fn new(passphrase: &str, preserve_mac_oui: bool, scrub_payload: bool) -> Self {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(b"mash-pcap-anonymizer-v1").expect("HMAC key init");
        mac.update(passphrase.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Self {
            key,
            preserve_mac_oui,
            scrub_payload,
        }
    }

    /// Pseudonymize a 6-byte Ethernet MAC address consistently.
    pub fn anonymize_mac(&self, mac_addr: [u8; 6]) -> [u8; 6] {
        if mac_addr == [0xff; 6] || mac_addr == [0x00; 6] {
            return mac_addr;
        }
        let digest = self.prf_tag(b"mac", &mac_addr);
        let mut out = mac_addr;
        if self.preserve_mac_oui {
            out[3] = digest[0];
            out[4] = digest[1];
            out[5] = digest[2];
        } else {
            out[0] = (digest[0] & 0xfe) | 0x02; // locally administered unicast
            out[1] = digest[1];
            out[2] = digest[2];
            out[3] = digest[3];
            out[4] = digest[4];
            out[5] = digest[5];
        }
        out
    }

    /// Pseudonymize an IPv4 address while preserving `/24` subnet grouping.
    pub fn anonymize_ipv4(&self, ip: [u8; 4]) -> [u8; 4] {
        if ip == [127, 0, 0, 1] || ip == [255, 255, 255, 255] || ip == [0, 0, 0, 0] {
            return ip;
        }
        let net_tag = self.prf_tag(b"ipv4-net24", &ip[..3]);
        let host_tag = self.prf_tag(b"ipv4-host", &ip);
        [
            10,
            net_tag[0],
            net_tag[1],
            host_tag[0].clamp(1, 254),
        ]
    }

    /// Pseudonymize an IPv6 address into the `fd00::/8` ULA range while preserving `/64` prefix grouping.
    pub fn anonymize_ipv6(&self, ip: [u8; 16]) -> [u8; 16] {
        let pfx = self.prf_tag(b"ipv6-pfx64", &ip[..8]);
        let iid = self.prf_tag(b"ipv6-iid64", &ip);
        let mut out = [0u8; 16];
        out[0] = 0xfd;
        out[1..8].copy_from_slice(&pfx[..7]);
        out[8..16].copy_from_slice(&iid[..8]);
        out
    }

    /// Anonymize a `Frame` in-place (Ethernet MACs, IPv4/IPv6 addresses, ARP addresses, and optional payload scrubbing).
    pub fn anonymize_frame(&self, frame: &mut Frame) {
        if frame.link_type != LinkType::Ethernet || frame.data.len() < 14 {
            return;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&frame.data[0..6]);
        src_mac.copy_from_slice(&frame.data[6..12]);
        frame.data[0..6].copy_from_slice(&self.anonymize_mac(dst_mac));
        frame.data[6..12].copy_from_slice(&self.anonymize_mac(src_mac));

        let mut ethertype = u16::from_be_bytes([frame.data[12], frame.data[13]]);
        let mut l3_off = 14usize;
        if (ethertype == 0x8100 || ethertype == 0x88a8) && frame.data.len() >= 18 {
            ethertype = u16::from_be_bytes([frame.data[16], frame.data[17]]);
            l3_off = 18;
        }

        match ethertype {
            0x0800 if frame.data.len() >= l3_off + 20 => {
                let ihl = ((frame.data[l3_off] & 0x0f) as usize) * 4;
                let proto = frame.data[l3_off + 9];
                let mut src_ip = [0u8; 4];
                let mut dst_ip = [0u8; 4];
                src_ip.copy_from_slice(&frame.data[l3_off + 12..l3_off + 16]);
                dst_ip.copy_from_slice(&frame.data[l3_off + 16..l3_off + 20]);
                frame.data[l3_off + 12..l3_off + 16]
                    .copy_from_slice(&self.anonymize_ipv4(src_ip));
                frame.data[l3_off + 16..l3_off + 20]
                    .copy_from_slice(&self.anonymize_ipv4(dst_ip));

                if self.scrub_payload {
                    let l4_off = l3_off + ihl.max(20);
                    let payload_off = match proto {
                        6 if frame.data.len() >= l4_off + 20 => {
                            let tcp_hdr_len = ((frame.data[l4_off + 12] >> 4) as usize) * 4;
                            l4_off + tcp_hdr_len.max(20)
                        }
                        17 => l4_off + 8,
                        _ => l4_off,
                    };
                    if payload_off < frame.data.len() {
                        frame.data[payload_off..].fill(0);
                    }
                }
            }
            0x86dd if frame.data.len() >= l3_off + 40 => {
                let mut src_ip6 = [0u8; 16];
                let mut dst_ip6 = [0u8; 16];
                src_ip6.copy_from_slice(&frame.data[l3_off + 8..l3_off + 24]);
                dst_ip6.copy_from_slice(&frame.data[l3_off + 24..l3_off + 40]);
                frame.data[l3_off + 8..l3_off + 24]
                    .copy_from_slice(&self.anonymize_ipv6(src_ip6));
                frame.data[l3_off + 24..l3_off + 40]
                    .copy_from_slice(&self.anonymize_ipv6(dst_ip6));
            }
            0x0806 if frame.data.len() >= l3_off + 28 => {
                // Ethernet + IPv4 ARP
                let mut sha = [0u8; 6];
                let mut spa = [0u8; 4];
                let mut tha = [0u8; 6];
                let mut tpa = [0u8; 4];
                sha.copy_from_slice(&frame.data[l3_off + 8..l3_off + 14]);
                spa.copy_from_slice(&frame.data[l3_off + 14..l3_off + 18]);
                tha.copy_from_slice(&frame.data[l3_off + 18..l3_off + 24]);
                tpa.copy_from_slice(&frame.data[l3_off + 24..l3_off + 28]);
                frame.data[l3_off + 8..l3_off + 14].copy_from_slice(&self.anonymize_mac(sha));
                frame.data[l3_off + 14..l3_off + 18].copy_from_slice(&self.anonymize_ipv4(spa));
                frame.data[l3_off + 18..l3_off + 24].copy_from_slice(&self.anonymize_mac(tha));
                frame.data[l3_off + 24..l3_off + 28].copy_from_slice(&self.anonymize_ipv4(tpa));
            }
            _ => {}
        }
    }

    fn prf_tag(&self, domain: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key).expect("HMAC init");
        mac.update(domain);
        mac.update(data);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
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

    #[test]
    fn tls12_prf_and_aes_gcm_decryption_roundtrip() {
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let master = [0x33u8; 48];
        let keys = Tls12TrafficKeys::from_master_secret(
            Tls12CipherSuite::Aes128GcmSha256,
            &master,
            &cr,
            &sr,
        )
        .unwrap();

        let explicit_nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&keys.client_write_iv);
        nonce[4..].copy_from_slice(&explicit_nonce);

        let plaintext = b"HTTP/1.1 200 OK\r\n\r\n";
        let seq_num = 0u64;
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq_num.to_be_bytes());
        aad[8] = 23;
        aad[9..11].copy_from_slice(&0x0303u16.to_be_bytes());
        aad[11..13].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());

        let cipher = Aes128Gcm::new_from_slice(&keys.client_write_key).unwrap();
        let ct = cipher
            .encrypt(
                AesNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&explicit_nonce);
        body.extend_from_slice(&ct);

        let dec = keys.decrypt_record(true, seq_num, 23, 0x0303, &body).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn pcap_anonymizer_preserves_subnet_consistency() {
        let anon = PcapAnonymizer::new("secret-key", true, false);
        let a1 = anon.anonymize_ipv4([192, 168, 10, 5]);
        let a2 = anon.anonymize_ipv4([192, 168, 10, 99]);
        assert_eq!(a1[..3], a2[..3]);
        assert_ne!(a1[3], a2[3]);

        let mac = anon.anonymize_mac([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(&mac[..3], &[0x00, 0x1a, 0x2b]);
        assert_ne!(&mac[3..], &[0x3c, 0x4d, 0x5e]);
    }
}
