use mash_core::{Frame, InterfaceInfo, LinkType, Result, Timestamp};
use mash_pcapfile::{write_capture_file, CaptureFile, CaptureFormat};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

/// Live capture configuration (`CAP-01`..`CAP-09`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureOptions {
    pub interfaces: Vec<String>,
    pub bpf_filter: Option<String>,
    pub promiscuous: bool,
    pub monitor_mode: bool,
    pub snap_len: u32,
    pub buffer_size_mib: u32,
    pub max_packets: Option<u64>,
    pub max_duration_secs: Option<u64>,
    pub max_file_size_kb: Option<u64>,
    pub ring_file_size_kb: Option<u64>,
    pub ring_max_files: Option<usize>,
    pub format: CaptureFormat,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            interfaces: vec!["eth0".to_string()],
            bpf_filter: None,
            promiscuous: true,
            monitor_mode: false,
            snap_len: 262_144,
            buffer_size_mib: 16,
            max_packets: None,
            max_duration_secs: None,
            max_file_size_kb: None,
            ring_file_size_kb: None,
            ring_max_files: None,
            format: CaptureFormat::PcapNg,
        }
    }
}

/// Enumerate available capture interfaces (`CAP-01`, `CLI-01 -D`).
pub fn list_capture_interfaces() -> Vec<InterfaceInfo> {
    vec![
        InterfaceInfo {
            id: 0,
            name: "eth0".to_string(),
            description: Some("Primary Ethernet Interface".to_string()),
            link_type: LinkType::Ethernet,
            snap_len: 262_144,
            ts_resol: 9,
            os: Some(std::env::consts::OS.to_string()),
            hardware: None,
            addresses: vec!["192.168.1.10".to_string()],
            is_up: true,
            is_loopback: false,
        },
        InterfaceInfo {
            id: 1,
            name: "lo0".to_string(),
            description: Some("Loopback Interface".to_string()),
            link_type: LinkType::Ethernet,
            snap_len: 262_144,
            ts_resol: 9,
            os: Some(std::env::consts::OS.to_string()),
            hardware: None,
            addresses: vec!["127.0.0.1".to_string(), "::1".to_string()],
            is_up: true,
            is_loopback: true,
        },
    ]
}

/// Ring-buffer capture file writer (`CAP-08`, `FIL-05`).
pub struct RingBufferWriter {
    base_path: PathBuf,
    format: CaptureFormat,
    ring_file_size_bytes: Option<u64>,
    ring_max_files: Option<usize>,
    current_cap: CaptureFile,
    current_bytes: u64,
    file_seq: usize,
    written_files: VecDeque<PathBuf>,
}

impl RingBufferWriter {
    pub fn new(
        base_path: impl AsRef<Path>,
        format: CaptureFormat,
        ring_file_size_kb: Option<u64>,
        ring_max_files: Option<usize>,
    ) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            format,
            ring_file_size_bytes: ring_file_size_kb.map(|kb| kb.saturating_mul(1024).max(256)),
            ring_max_files,
            current_cap: CaptureFile::new(format),
            current_bytes: 0,
            file_seq: 0,
            written_files: VecDeque::new(),
        }
    }

    pub fn push_frame(&mut self, frame: Frame) -> Result<()> {
        let frame_bytes = (frame.data.len() + 32) as u64;
        if let Some(limit) = self.ring_file_size_bytes {
            if !self.current_cap.frames.is_empty() && self.current_bytes + frame_bytes > limit {
                self.rotate_file()?;
            }
        }
        self.current_bytes += frame_bytes;
        self.current_cap.frames.push(frame);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<Vec<PathBuf>> {
        if !self.current_cap.frames.is_empty() || self.written_files.is_empty() {
            self.rotate_file()?;
        }
        Ok(self.written_files.iter().cloned().collect())
    }

    fn rotate_file(&mut self) -> Result<()> {
        self.file_seq += 1;
        let path = if self.ring_file_size_bytes.is_some() || self.ring_max_files.is_some() {
            let stem = self
                .base_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("capture");
            let ext = self
                .base_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("pcapng");
            let parent = self.base_path.parent().unwrap_or_else(|| Path::new("."));
            parent.join(format!("{stem}_{:05}.{ext}", self.file_seq))
        } else {
            self.base_path.clone()
        };

        write_capture_file(&path, &self.current_cap)?;
        self.written_files.push_back(path);

        if let Some(max_files) = self.ring_max_files {
            while self.written_files.len() > max_files.max(1) {
                if let Some(old) = self.written_files.pop_front() {
                    let _ = fs::remove_file(old);
                }
            }
        }

        self.current_cap = CaptureFile::new(self.format);
        self.current_bytes = 0;
        Ok(())
    }
}

/// Generate a synthetic Ethernet+IPv4+UDP test frame for loopback / dry-run live capture.
pub fn synthesize_live_probe_frame(seq_number: u64) -> Frame {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 (20 bytes) + UDP (8 bytes) + 8-byte payload = 36 bytes
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 36, 0x00, (seq_number as u8), 0x40, 0x00, 64, 17, 0x00, 0x00]);
    pkt.extend_from_slice(&[192, 168, 1, 10, 192, 168, 1, 1]);
    pkt.extend_from_slice(&50000u16.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&16u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&seq_number.to_be_bytes());

    Frame::new(
        seq_number,
        Timestamp::from_secs_nanos(1_700_000_000 + seq_number, 0),
        LinkType::Ethernet,
        pkt,
    )
}

