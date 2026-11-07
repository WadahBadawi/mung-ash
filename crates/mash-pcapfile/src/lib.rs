pub mod text2pcap;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use mash_core::{
    Frame, FrameFlags, InterfaceInfo, LinkType, MashError, NameResolver, PacketDirection, Result,
    Timestamp,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Maximum decompressed capture size in memory (512 MiB default safety bound for decompression bombs).
pub const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
/// Maximum single packet capture length (16 MiB).
pub const MAX_PACKET_LEN: usize = 16 * 1024 * 1024;

/// Underlying capture container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CaptureFormat {
    PcapMicros,
    PcapNanos,
    #[default]
    PcapNg,
}

impl CaptureFormat {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PcapMicros => "libpcap (microsecond)",
            Self::PcapNanos => "libpcap (nanosecond)",
            Self::PcapNg => "pcapng",
        }
    }
}

/// Stream compression wrapper around a capture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CompressionFormat {
    #[default]
    None,
    Gzip,
    Lz4,
}

/// Warning generated while recovering a truncated or partially corrupt capture file (FIL-07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureWarning {
    pub byte_offset: usize,
    pub message: String,
}

/// DNS name resolution record stored in a pcapng Name Resolution Block (NRB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameRecord {
    Ipv4([u8; 4], String),
    Ipv6([u8; 16], String),
}

/// Embedded decryption secret from a pcapng Decryption Secrets Block (DSB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionSecret {
    /// Secret type code (e.g., `0x544c534b` = `"TLSK"` for TLS Key Log).
    pub secrets_type: u32,
    pub data: Vec<u8>,
}

/// Interface capture statistics from a pcapng Interface Statistics Block (ISB).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub interface_id: u32,
    pub timestamp: Timestamp,
    pub isb_starttime: Option<Timestamp>,
    pub isb_endtime: Option<Timestamp>,
    pub if_recv: Option<u64>,
    pub if_drop: Option<u64>,
    pub filter_accept: Option<u64>,
    pub os_drop: Option<u64>,
    pub usr_deliv: Option<u64>,
}

/// Compact per-frame index record for random access and virtualized packet lists (PERF-06: <= 150 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameIndexEntry {
    pub number: u64,
    pub file_offset: u64,
    pub timestamp: Timestamp,
    pub captured_len: u32,
    pub orig_len: u32,
    pub interface_id: u16,
    pub link_type_raw: u16,
}

/// Parsed capture container with all metadata, frames, and recovery warnings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureFile {
    pub format: CaptureFormat,
    pub compression: CompressionFormat,
    pub section_comments: Vec<String>,
    pub os: Option<String>,
    pub hardware: Option<String>,
    pub user_appl: Option<String>,
    pub interfaces: Vec<InterfaceInfo>,
    pub frames: Vec<Frame>,
    pub name_records: Vec<NameRecord>,
    pub decryption_secrets: Vec<DecryptionSecret>,
    pub interface_stats: Vec<InterfaceStats>,
    pub warnings: Vec<CaptureWarning>,
    pub index: Vec<FrameIndexEntry>,
}

impl CaptureFile {
    pub fn new(format: CaptureFormat) -> Self {
        Self {
            format,
            ..Self::default()
        }
    }

    /// Populate a `NameResolver` with any pcapng NRB records present in this capture.
    pub fn populate_name_resolver(&self, resolver: &mut NameResolver) {
        for rec in &self.name_records {
            match rec {
                NameRecord::Ipv4(ip, host) => resolver.learn_dns_v4(*ip, host.clone()),
                NameRecord::Ipv6(ip, host) => resolver.learn_dns_v6(*ip, host.clone()),
            }
        }
    }
}

/// Mode for merging multiple capture files (`mash-merge` / `CLI-05`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeMode {
    /// Interleave packets in chronological timestamp order.
    Chronological,
    /// Append packets from each file sequentially in input order.
    Concatenate,
}

/// Merge multiple `CaptureFile` instances into a single `CaptureFile`.
pub fn merge_captures(
    files: &[CaptureFile],
    mode: MergeMode,
    format: CaptureFormat,
) -> CaptureFile {
    let mut out = CaptureFile::new(format);
    let mut all_frames: Vec<Frame> = Vec::new();

    for file in files {
        let iface_offset = out.interfaces.len() as u32;
        if file.interfaces.is_empty() {
            let mut default_if = InterfaceInfo {
                id: iface_offset,
                ..InterfaceInfo::default()
            };
            if let Some(first) = file.frames.first() {
                default_if.link_type = first.link_type;
            }
            out.interfaces.push(default_if);
        } else {
            for (idx, iface) in file.interfaces.iter().enumerate() {
                let mut cloned = iface.clone();
                cloned.id = iface_offset + (idx as u32);
                out.interfaces.push(cloned);
            }
        }

        out.name_records.extend(file.name_records.iter().cloned());
        out.decryption_secrets
            .extend(file.decryption_secrets.iter().cloned());

        for frame in &file.frames {
            let mut f = frame.clone();
            f.interface_id += iface_offset;
            all_frames.push(f);
        }
    }

    if mode == MergeMode::Chronological {
        all_frames.sort_by_key(|f| f.timestamp);
    }

    for (idx, mut frame) in all_frames.into_iter().enumerate() {
        frame.number = (idx + 1) as u64;
        out.index.push(FrameIndexEntry {
            number: frame.number,
            file_offset: 0,
            timestamp: frame.timestamp,
            captured_len: frame.captured_len,
            orig_len: frame.orig_len,
            interface_id: frame.interface_id as u16,
            link_type_raw: frame.link_type.to_u32() as u16,
        });
        out.frames.push(frame);
    }

    out
}

/// Read and parse a capture file from disk, transparently decompressing `.gz` or `.lz4`.
pub fn read_capture_file(path: impl AsRef<Path>) -> Result<CaptureFile> {
    let mut file = File::open(path.as_ref())?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    read_capture_bytes(&raw)
}

/// Read and parse a capture from an in-memory byte slice, transparently decompressing Gzip or LZ4.
pub fn read_capture_bytes(raw: &[u8]) -> Result<CaptureFile> {
    let (decompressed, compression) = decompress_if_needed(raw)?;
    let data = decompressed.as_deref().unwrap_or(raw);

    if data.len() < 4 {
        return Err(MashError::Format(
            "Capture file is shorter than 4 bytes".to_string(),
        ));
    }

    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mut cap = match magic_le {
        0xa1b2_c3d4 => parse_classic_pcap(data, true, false)?,
        0xd4c3_b2a1 => parse_classic_pcap(data, false, false)?,
        0xa1b2_3c4d => parse_classic_pcap(data, true, true)?,
        0x4d3c_b2a1 => parse_classic_pcap(data, false, true)?,
        0x0a0d_0d0a => parse_pcapng(data)?,
        other => {
            return Err(MashError::Format(format!(
                "Unrecognized capture magic number: 0x{other:08x}"
            )));
        }
    };
    cap.compression = compression;
    Ok(cap)
}

fn decompress_if_needed(raw: &[u8]) -> Result<(Option<Vec<u8>>, CompressionFormat)> {
    // Gzip magic: 0x1f 0x8b
    if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        let decoder = GzDecoder::new(raw);
        let mut limited = decoder.take((MAX_DECOMPRESSED_BYTES as u64) + 1);
        let mut out = Vec::new();
        limited.read_to_end(&mut out)?;
        if out.len() > MAX_DECOMPRESSED_BYTES {
            return Err(MashError::LimitExceeded(
                "Gzip decompressed capture exceeds 512 MiB limit".to_string(),
            ));
        }
        return Ok((Some(out), CompressionFormat::Gzip));
    }

    // LZ4 frame magic: 0x04 0x22 0x4d 0x18
    if raw.len() >= 4 && raw[0..4] == [0x04, 0x22, 0x4d, 0x18] {
        let mut decoder = lz4_flex::frame::FrameDecoder::new(raw);
        let mut limited = (&mut decoder).take((MAX_DECOMPRESSED_BYTES as u64) + 1);
        let mut out = Vec::new();
        limited.read_to_end(&mut out)?;
        if out.len() > MAX_DECOMPRESSED_BYTES {
            return Err(MashError::LimitExceeded(
                "LZ4 decompressed capture exceeds 512 MiB limit".to_string(),
            ));
        }
        return Ok((Some(out), CompressionFormat::Lz4));
    }

    Ok((None, CompressionFormat::None))
}

fn read_u16(bytes: &[u8], le: bool) -> u16 {
    let arr = [bytes[0], bytes[1]];
    if le {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    }
}

fn read_u32(bytes: &[u8], le: bool) -> u32 {
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if le {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

fn read_u64(bytes: &[u8], le: bool) -> u64 {
    let arr = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ];
    if le {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    }
}

fn parse_classic_pcap(data: &[u8], le: bool, nanos: bool) -> Result<CaptureFile> {
    if data.len() < 24 {
        return Err(MashError::Format(
            "Classic PCAP header truncated (< 24 bytes)".to_string(),
        ));
    }

    let version_major = read_u16(&data[4..6], le);
    let version_minor = read_u16(&data[6..8], le);
    let snap_len = read_u32(&data[16..20], le);
    let network = read_u32(&data[20..24], le);
    let link_type = LinkType::from_u32(network);

    let format = if nanos {
        CaptureFormat::PcapNanos
    } else {
        CaptureFormat::PcapMicros
    };
    let mut cap = CaptureFile::new(format);
    if version_major != 2 || version_minor != 4 {
        cap.warnings.push(CaptureWarning {
            byte_offset: 4,
            message: format!("Non-standard PCAP version {version_major}.{version_minor}"),
        });
    }

    cap.interfaces.push(InterfaceInfo {
        id: 0,
        name: "pcap0".to_string(),
        description: None,
        link_type,
        snap_len,
        ts_resol: if nanos { 9 } else { 6 },
        os: None,
        hardware: None,
        addresses: Vec::new(),
        is_up: true,
        is_loopback: link_type == LinkType::Null,
    });

    let mut pos = 24usize;
    let mut frame_no = 0u64;

    while pos < data.len() {
        if pos + 16 > data.len() {
            cap.warnings.push(CaptureWarning {
                byte_offset: pos,
                message: format!(
                    "Truncated classic PCAP packet header at offset {pos} ({} bytes remaining)",
                    data.len() - pos
                ),
            });
            break;
        }

        let record_offset = pos as u64;
        let ts_sec = read_u32(&data[pos..pos + 4], le) as u64;
        let ts_sub = read_u32(&data[pos + 4..pos + 8], le);
        let incl_len = read_u32(&data[pos + 8..pos + 12], le);
        let orig_len = read_u32(&data[pos + 12..pos + 16], le);
        pos += 16;

        if (incl_len as usize) > MAX_PACKET_LEN {
            cap.warnings.push(CaptureWarning {
                byte_offset: record_offset as usize,
                message: format!("Corrupt packet incl_len {incl_len} exceeds 16 MiB cap"),
            });
            break;
        }

        let end = pos.saturating_add(incl_len as usize);
        if end > data.len() {
            cap.warnings.push(CaptureWarning {
                byte_offset: record_offset as usize,
                message: format!(
                    "Truncated packet payload at offset {pos}: expected {incl_len} bytes, found {}",
                    data.len() - pos
                ),
            });
            break;
        }

        let subsec_nanos = if nanos {
            ts_sub
        } else {
            ts_sub.saturating_mul(1_000)
        };
        let timestamp = Timestamp::from_secs_nanos(ts_sec, subsec_nanos);
        let payload = data[pos..end].to_vec();
        pos = end;

        frame_no += 1;
        cap.index.push(FrameIndexEntry {
            number: frame_no,
            file_offset: record_offset,
            timestamp,
            captured_len: incl_len,
            orig_len,
            interface_id: 0,
            link_type_raw: link_type.to_u32() as u16,
        });
        cap.frames.push(Frame {
            number: frame_no,
            timestamp,
            captured_len: incl_len,
            orig_len,
            link_type,
            interface_id: 0,
            comments: Vec::new(),
            flags: FrameFlags::default(),
            data: payload,
            extra_sources: Vec::new(),
        });
    }

    Ok(cap)
}

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

fn parse_pcapng(data: &[u8]) -> Result<CaptureFile> {
    let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
    let mut pos = 0usize;
    let mut le = true;
    let mut frame_no = 0u64;

    while pos < data.len() {
        if pos + 12 > data.len() {
            cap.warnings.push(CaptureWarning {
                byte_offset: pos,
                message: format!(
                    "Truncated pcapng block header at offset {pos} ({} bytes remaining)",
                    data.len() - pos
                ),
            });
            break;
        }

        let block_offset = pos;
        let raw_type = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if raw_type == 0x0a0d_0d0a {
            // Section Header Block determines endianness via byte-order magic at pos + 8
            if pos + 16 > data.len() {
                cap.warnings.push(CaptureWarning {
                    byte_offset: pos,
                    message: "Truncated pcapng Section Header Block".to_string(),
                });
                break;
            }
            let bom = u32::from_le_bytes([
                data[pos + 8],
                data[pos + 9],
                data[pos + 10],
                data[pos + 11],
            ]);
            if bom == 0x1a2b_3c4d {
                le = true;
            } else if bom == 0x4d3c_2b1a {
                le = false;
            } else {
                cap.warnings.push(CaptureWarning {
                    byte_offset: pos + 8,
                    message: format!("Invalid pcapng byte-order magic 0x{bom:08x}"),
                });
                break;
            }
        }

        let block_type = read_u32(&data[pos..pos + 4], le);
        let block_total_len = read_u32(&data[pos + 4..pos + 8], le) as usize;

        if block_total_len < 12 || !block_total_len.is_multiple_of(4) {
            cap.warnings.push(CaptureWarning {
                byte_offset: pos,
                message: format!("Invalid pcapng block total length {block_total_len}"),
            });
            break;
        }

        if pos.saturating_add(block_total_len) > data.len() {
            cap.warnings.push(CaptureWarning {
                byte_offset: pos,
                message: format!(
                    "Truncated pcapng block (type 0x{block_type:08x}): needed {block_total_len} bytes, {} available",
                    data.len() - pos
                ),
            });
            break;
        }

        let body = &data[pos + 8..pos + block_total_len - 4];
        let trailing_len =
            read_u32(&data[pos + block_total_len - 4..pos + block_total_len], le) as usize;
        if trailing_len != block_total_len {
            cap.warnings.push(CaptureWarning {
                byte_offset: pos + block_total_len - 4,
                message: format!(
                    "Mismatched pcapng trailing block length ({trailing_len} != {block_total_len})"
                ),
            });
        }

        match block_type {
            // Section Header Block (SHB)
            0x0a0d_0d0a => {
                if body.len() >= 16 {
                    let opts = &body[16..];
                    for (code, val) in parse_options(opts, le) {
                        let text = String::from_utf8_lossy(val)
                            .trim_end_matches('\0')
                            .to_string();
                        match code {
                            1 => cap.section_comments.push(text),
                            2 => cap.hardware = Some(text),
                            3 => cap.os = Some(text),
                            4 => cap.user_appl = Some(text),
                            _ => {}
                        }
                    }
                }
            }
            // Interface Description Block (IDB)
            0x0000_0001 => {
                if body.len() >= 8 {
                    let link_raw = read_u16(&body[0..2], le) as u32;
                    let snap_len = read_u32(&body[4..8], le);
                    let id = cap.interfaces.len() as u32;
                    let mut iface = InterfaceInfo {
                        id,
                        name: format!("eth{id}"),
                        description: None,
                        link_type: LinkType::from_u32(link_raw),
                        snap_len,
                        ts_resol: 6, // default 10^-6 per pcapng spec
                        os: None,
                        hardware: None,
                        addresses: Vec::new(),
                        is_up: true,
                        is_loopback: link_raw == 0,
                    };
                    for (code, val) in parse_options(&body[8..], le) {
                        match code {
                            2 => {
                                iface.name = String::from_utf8_lossy(val)
                                    .trim_end_matches('\0')
                                    .to_string()
                            }
                            3 => {
                                iface.description = Some(
                                    String::from_utf8_lossy(val)
                                        .trim_end_matches('\0')
                                        .to_string(),
                                )
                            }
                            9 if !val.is_empty() => {
                                iface.ts_resol = val[0];
                            }
                            12 => {
                                iface.os = Some(
                                    String::from_utf8_lossy(val)
                                        .trim_end_matches('\0')
                                        .to_string(),
                                )
                            }
                            15 => {
                                iface.hardware = Some(
                                    String::from_utf8_lossy(val)
                                        .trim_end_matches('\0')
                                        .to_string(),
                                )
                            }
                            _ => {}
                        }
                    }
                    cap.interfaces.push(iface);
                }
            }
            // Enhanced Packet Block (EPB)
            0x0000_0006 => {
                if body.len() >= 20 {
                    let interface_id = read_u32(&body[0..4], le);
                    let ts_high = read_u32(&body[4..8], le) as u64;
                    let ts_low = read_u32(&body[8..12], le) as u64;
                    let captured_len = read_u32(&body[12..16], le);
                    let orig_len = read_u32(&body[16..20], le);

                    let padded_len = align4(captured_len as usize);
                    if (captured_len as usize) <= MAX_PACKET_LEN && 20 + padded_len <= body.len() {
                        let pkt_bytes = body[20..20 + (captured_len as usize)].to_vec();
                        let opts_slice = &body[20 + padded_len..];

                        let mut comments = Vec::new();
                        let mut flags = FrameFlags::default();
                        for (code, val) in parse_options(opts_slice, le) {
                            match code {
                                1 => {
                                    comments.push(
                                        String::from_utf8_lossy(val)
                                            .trim_end_matches('\0')
                                            .to_string(),
                                    );
                                }
                                2 if val.len() >= 4 => {
                                    let epb_flags = read_u32(&val[0..4], le);
                                    flags.direction = match epb_flags & 0b11 {
                                        1 => PacketDirection::Inbound,
                                        2 => PacketDirection::Outbound,
                                        _ => PacketDirection::Unknown,
                                    };
                                }
                                _ => {}
                            }
                        }

                        let (link_type, ts_resol) = cap
                            .interfaces
                            .get(interface_id as usize)
                            .map(|i| (i.link_type, i.ts_resol))
                            .unwrap_or((LinkType::Ethernet, 6));

                        let raw_ts = (ts_high << 32) | ts_low;
                        let timestamp = decode_pcapng_timestamp(raw_ts, ts_resol);

                        frame_no += 1;
                        cap.index.push(FrameIndexEntry {
                            number: frame_no,
                            file_offset: block_offset as u64,
                            timestamp,
                            captured_len,
                            orig_len,
                            interface_id: interface_id as u16,
                            link_type_raw: link_type.to_u32() as u16,
                        });
                        cap.frames.push(Frame {
                            number: frame_no,
                            timestamp,
                            captured_len,
                            orig_len,
                            link_type,
                            interface_id,
                            comments,
                            flags,
                            data: pkt_bytes,
                            extra_sources: Vec::new(),
                        });
                    } else {
                        cap.warnings.push(CaptureWarning {
                            byte_offset: block_offset,
                            message: "EPB captured_len exceeds block body".to_string(),
                        });
                    }
                }
            }
            // Simple Packet Block (SPB)
            0x0000_0003 => {
                if body.len() >= 4 {
                    let orig_len = read_u32(&body[0..4], le);
                    let pkt_data = &body[4..];
                    let link_type = cap
                        .interfaces
                        .first()
                        .map(|i| i.link_type)
                        .unwrap_or(LinkType::Ethernet);
                    let snap_len = cap
                        .interfaces
                        .first()
                        .map(|i| i.snap_len)
                        .unwrap_or(262_144);
                    let captured_len = (pkt_data.len() as u32).min(orig_len).min(snap_len);
                    let payload = pkt_data[..captured_len as usize].to_vec();

                    frame_no += 1;
                    cap.index.push(FrameIndexEntry {
                        number: frame_no,
                        file_offset: block_offset as u64,
                        timestamp: Timestamp::ZERO,
                        captured_len,
                        orig_len,
                        interface_id: 0,
                        link_type_raw: link_type.to_u32() as u16,
                    });
                    cap.frames.push(Frame {
                        number: frame_no,
                        timestamp: Timestamp::ZERO,
                        captured_len,
                        orig_len,
                        link_type,
                        interface_id: 0,
                        comments: Vec::new(),
                        flags: FrameFlags::default(),
                        data: payload,
                        extra_sources: Vec::new(),
                    });
                }
            }
            // Name Resolution Block (NRB)
            0x0000_0004 => {
                parse_nrb_records(body, le, &mut cap.name_records);
            }
            // Interface Statistics Block (ISB)
            0x0000_0005 => {
                if body.len() >= 12 {
                    let interface_id = read_u32(&body[0..4], le);
                    let ts_high = read_u32(&body[4..8], le) as u64;
                    let ts_low = read_u32(&body[8..12], le) as u64;
                    let ts_resol = cap
                        .interfaces
                        .get(interface_id as usize)
                        .map(|i| i.ts_resol)
                        .unwrap_or(6);
                    let timestamp = decode_pcapng_timestamp((ts_high << 32) | ts_low, ts_resol);
                    let mut stats = InterfaceStats {
                        interface_id,
                        timestamp,
                        ..InterfaceStats::default()
                    };
                    for (code, val) in parse_options(&body[12..], le) {
                        match code {
                            2 if val.len() >= 8 => {
                                let hi = read_u32(&val[0..4], le) as u64;
                                let lo = read_u32(&val[4..8], le) as u64;
                                stats.isb_starttime =
                                    Some(decode_pcapng_timestamp((hi << 32) | lo, ts_resol));
                            }
                            3 if val.len() >= 8 => {
                                let hi = read_u32(&val[0..4], le) as u64;
                                let lo = read_u32(&val[4..8], le) as u64;
                                stats.isb_endtime =
                                    Some(decode_pcapng_timestamp((hi << 32) | lo, ts_resol));
                            }
                            4 if val.len() >= 8 => stats.if_recv = Some(read_u64(&val[0..8], le)),
                            5 if val.len() >= 8 => stats.if_drop = Some(read_u64(&val[0..8], le)),
                            6 if val.len() >= 8 => {
                                stats.filter_accept = Some(read_u64(&val[0..8], le))
                            }
                            7 if val.len() >= 8 => stats.os_drop = Some(read_u64(&val[0..8], le)),
                            8 if val.len() >= 8 => stats.usr_deliv = Some(read_u64(&val[0..8], le)),
                            _ => {}
                        }
                    }
                    cap.interface_stats.push(stats);
                }
            }
            // Decryption Secrets Block (DSB)
            0x0000_000a if body.len() >= 8 => {
                let secrets_type = read_u32(&body[0..4], le);
                let secrets_len = read_u32(&body[4..8], le) as usize;
                if 8 + secrets_len <= body.len() {
                    cap.decryption_secrets.push(DecryptionSecret {
                        secrets_type,
                        data: body[8..8 + secrets_len].to_vec(),
                    });
                }
            }
            _ => {
                // Unknown or vendor block: skip gracefully per pcapng specification.
            }
        }

        pos += block_total_len;
    }

    Ok(cap)
}

fn decode_pcapng_timestamp(raw: u64, ts_resol: u8) -> Timestamp {
    let raw_128 = raw as i128;
    if (ts_resol & 0x80) == 0 {
        // Negative power of 10
        let exp = (ts_resol & 0x7f) as u32;
        if exp <= 9 {
            let scale = 10_i128.pow(9 - exp);
            Timestamp::from_nanos(raw_128.saturating_mul(scale))
        } else {
            let div = 10_i128.pow(exp - 9);
            Timestamp::from_nanos(raw_128 / div)
        }
    } else {
        // Negative power of 2
        let shift = (ts_resol & 0x7f) as u32;
        if shift < 64 {
            let nanos = (raw_128.saturating_mul(1_000_000_000)) >> shift;
            Timestamp::from_nanos(nanos)
        } else {
            Timestamp::ZERO
        }
    }
}

fn parse_options(mut buf: &[u8], le: bool) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let code = read_u16(&buf[0..2], le);
        let len = read_u16(&buf[2..4], le) as usize;
        buf = &buf[4..];
        if code == 0 {
            break;
        }
        let padded = align4(len);
        if padded > buf.len() {
            break;
        }
        out.push((code, &buf[..len]));
        buf = &buf[padded..];
    }
    out
}

fn parse_nrb_records(mut buf: &[u8], le: bool, out: &mut Vec<NameRecord>) {
    while buf.len() >= 4 {
        let rec_type = read_u16(&buf[0..2], le);
        let rec_len = read_u16(&buf[2..4], le) as usize;
        buf = &buf[4..];
        if rec_type == 0 {
            break;
        }
        let padded = align4(rec_len);
        if padded > buf.len() {
            break;
        }
        let val = &buf[..rec_len];
        match rec_type {
            1 if val.len() > 4 => {
                let ip = [val[0], val[1], val[2], val[3]];
                for name_bytes in val[4..].split(|&b| b == 0) {
                    if !name_bytes.is_empty() {
                        if let Ok(s) = std::str::from_utf8(name_bytes) {
                            out.push(NameRecord::Ipv4(ip, s.to_string()));
                        }
                    }
                }
            }
            2 if val.len() > 16 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&val[0..16]);
                for name_bytes in val[16..].split(|&b| b == 0) {
                    if !name_bytes.is_empty() {
                        if let Ok(s) = std::str::from_utf8(name_bytes) {
                            out.push(NameRecord::Ipv6(ip, s.to_string()));
                        }
                    }
                }
            }
            _ => {}
        }
        buf = &buf[padded..];
    }
}

/// Serialize a `CaptureFile` into classic libpcap format (`.pcap`).
pub fn write_pcap_bytes(cap: &CaptureFile, nanos: bool) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(24 + cap.frames.len() * 128);
    let magic: u32 = if nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
    let link_type = cap
        .interfaces
        .first()
        .map(|i| i.link_type)
        .or_else(|| cap.frames.first().map(|f| f.link_type))
        .unwrap_or(LinkType::Ethernet);
    let snap_len = cap
        .interfaces
        .first()
        .map(|i| i.snap_len)
        .unwrap_or(262_144);

    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&snap_len.to_le_bytes());
    out.extend_from_slice(&link_type.to_u32().to_le_bytes());

    for frame in &cap.frames {
        let secs = frame.timestamp.secs().max(0) as u32;
        let sub = if nanos {
            frame.timestamp.subsec_nanos()
        } else {
            frame.timestamp.subsec_micros()
        };
        let incl_len = frame.data.len() as u32;
        let orig_len = frame.orig_len.max(incl_len);

        out.extend_from_slice(&secs.to_le_bytes());
        out.extend_from_slice(&sub.to_le_bytes());
        out.extend_from_slice(&incl_len.to_le_bytes());
        out.extend_from_slice(&orig_len.to_le_bytes());
        out.extend_from_slice(&frame.data);
    }

    Ok(out)
}

fn write_opt(buf: &mut Vec<u8>, code: u16, data: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
    let pad = align4(data.len()) - data.len();
    buf.extend(std::iter::repeat_n(0, pad));
}

fn write_opt_end(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
}

fn write_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let padded_body = align4(body.len());
    let total_len = (12 + padded_body) as u32;
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total_len.to_le_bytes());
    out.extend_from_slice(body);
    out.extend(std::iter::repeat_n(0, padded_body - body.len()));
    out.extend_from_slice(&total_len.to_le_bytes());
}

/// Serialize a `CaptureFile` into PCAPNG format (`.pcapng`), preserving interfaces, comments, NRB, and DSB.
pub fn write_pcapng_bytes(cap: &CaptureFile) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128 + cap.frames.len() * 128);

    // 1. Section Header Block (SHB)
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes()); // byte-order magic
    shb.extend_from_slice(&1u16.to_le_bytes()); // major 1
    shb.extend_from_slice(&0u16.to_le_bytes()); // minor 0
    shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length unspecified
    let mut has_shb_opts = false;
    for comment in &cap.section_comments {
        write_opt(&mut shb, 1, comment.as_bytes());
        has_shb_opts = true;
    }
    if let Some(hw) = &cap.hardware {
        write_opt(&mut shb, 2, hw.as_bytes());
        has_shb_opts = true;
    }
    if let Some(os) = &cap.os {
        write_opt(&mut shb, 3, os.as_bytes());
        has_shb_opts = true;
    }
    let appl = cap.user_appl.as_deref().unwrap_or("MUNG-ASH");
    write_opt(&mut shb, 4, appl.as_bytes());
    let _ = has_shb_opts;
    write_opt_end(&mut shb);
    write_block(&mut out, 0x0a0d_0d0a, &shb);

    // 2. Interface Description Blocks (IDBs)
    let default_if = InterfaceInfo {
        id: 0,
        name: "eth0".to_string(),
        description: None,
        link_type: cap
            .frames
            .first()
            .map(|f| f.link_type)
            .unwrap_or(LinkType::Ethernet),
        snap_len: 262_144,
        ts_resol: 9,
        os: None,
        hardware: None,
        addresses: Vec::new(),
        is_up: true,
        is_loopback: false,
    };
    let interfaces: &[InterfaceInfo] = if cap.interfaces.is_empty() {
        std::slice::from_ref(&default_if)
    } else {
        &cap.interfaces
    };

    for iface in interfaces {
        let mut idb = Vec::new();
        idb.extend_from_slice(&(iface.link_type.to_u32() as u16).to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes()); // reserved
        idb.extend_from_slice(&iface.snap_len.to_le_bytes());
        if !iface.name.is_empty() {
            write_opt(&mut idb, 2, iface.name.as_bytes());
        }
        if let Some(desc) = &iface.description {
            write_opt(&mut idb, 3, desc.as_bytes());
        }
        write_opt(&mut idb, 9, &[9u8]); // write timestamps in nanosecond resolution (10^-9)
        write_opt_end(&mut idb);
        write_block(&mut out, 0x0000_0001, &idb);
    }

    // 3. Name Resolution Block (NRB) if any records exist
    if !cap.name_records.is_empty() {
        let mut nrb = Vec::new();
        for rec in &cap.name_records {
            match rec {
                NameRecord::Ipv4(ip, host) => {
                    let mut val = Vec::with_capacity(4 + host.len() + 1);
                    val.extend_from_slice(ip);
                    val.extend_from_slice(host.as_bytes());
                    val.push(0);
                    write_opt(&mut nrb, 1, &val);
                }
                NameRecord::Ipv6(ip, host) => {
                    let mut val = Vec::with_capacity(16 + host.len() + 1);
                    val.extend_from_slice(ip);
                    val.extend_from_slice(host.as_bytes());
                    val.push(0);
                    write_opt(&mut nrb, 2, &val);
                }
            }
        }
        write_opt_end(&mut nrb);
        write_block(&mut out, 0x0000_0004, &nrb);
    }

    // 4. Decryption Secrets Blocks (DSB) if any secrets exist
    for secret in &cap.decryption_secrets {
        let mut dsb = Vec::with_capacity(8 + secret.data.len());
        dsb.extend_from_slice(&secret.secrets_type.to_le_bytes());
        dsb.extend_from_slice(&(secret.data.len() as u32).to_le_bytes());
        dsb.extend_from_slice(&secret.data);
        write_block(&mut out, 0x0000_000a, &dsb);
    }

    // 5. Enhanced Packet Blocks (EPBs)
    for frame in &cap.frames {
        let mut epb = Vec::with_capacity(32 + frame.data.len());
        let iface_id = if (frame.interface_id as usize) < interfaces.len() {
            frame.interface_id
        } else {
            0
        };
        let ts_nanos = frame.timestamp.nanos.max(0) as u64;
        let ts_high = (ts_nanos >> 32) as u32;
        let ts_low = (ts_nanos & 0xffff_ffff) as u32;
        let captured_len = frame.data.len() as u32;
        let orig_len = frame.orig_len.max(captured_len);

        epb.extend_from_slice(&iface_id.to_le_bytes());
        epb.extend_from_slice(&ts_high.to_le_bytes());
        epb.extend_from_slice(&ts_low.to_le_bytes());
        epb.extend_from_slice(&captured_len.to_le_bytes());
        epb.extend_from_slice(&orig_len.to_le_bytes());
        epb.extend_from_slice(&frame.data);
        let pad = align4(frame.data.len()) - frame.data.len();
        epb.extend(std::iter::repeat_n(0, pad));

        let mut has_opts = false;
        for comment in &frame.comments {
            write_opt(&mut epb, 1, comment.as_bytes());
            has_opts = true;
        }
        if frame.flags.direction != PacketDirection::Unknown {
            let dir_bits: u32 = match frame.flags.direction {
                PacketDirection::Inbound => 1,
                PacketDirection::Outbound => 2,
                PacketDirection::Unknown => 0,
            };
            write_opt(&mut epb, 2, &dir_bits.to_le_bytes());
            has_opts = true;
        }
        if has_opts {
            write_opt_end(&mut epb);
        }
        write_block(&mut out, 0x0000_0006, &epb);
    }

    Ok(out)
}

/// Write a `CaptureFile` to disk, automatically selecting PCAP vs PCAPNG and optional Gzip/LZ4 compression from file extension or `cap` settings.
pub fn write_capture_file(path: impl AsRef<Path>, cap: &CaptureFile) -> Result<()> {
    let path_str = path.as_ref().to_string_lossy().to_ascii_lowercase();
    let compression = if path_str.ends_with(".gz") {
        CompressionFormat::Gzip
    } else if path_str.ends_with(".lz4") {
        CompressionFormat::Lz4
    } else {
        cap.compression
    };

    let stripped = path_str
        .trim_end_matches(".gz")
        .trim_end_matches(".lz4");
    let raw_bytes = if stripped.ends_with(".pcap") {
        write_pcap_bytes(cap, cap.format == CaptureFormat::PcapNanos)?
    } else if stripped.ends_with(".pcapng") {
        write_pcapng_bytes(cap)?
    } else {
        match cap.format {
            CaptureFormat::PcapMicros => write_pcap_bytes(cap, false)?,
            CaptureFormat::PcapNanos => write_pcap_bytes(cap, true)?,
            CaptureFormat::PcapNg => write_pcapng_bytes(cap)?,
        }
    };

    let final_bytes = match compression {
        CompressionFormat::None => raw_bytes,
        CompressionFormat::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&raw_bytes)?;
            encoder.finish()?
        }
        CompressionFormat::Lz4 => {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
            encoder.write_all(&raw_bytes)?;
            encoder
                .finish()
                .map_err(|e| MashError::Format(format!("LZ4 encode error: {e}")))?
        }
    };

    let mut file = File::create(path.as_ref())?;
    file.write_all(&final_bytes)?;
    Ok(())
}

/// Format helper for displaying NRB records.
pub fn format_name_record(rec: &NameRecord) -> String {
    match rec {
        NameRecord::Ipv4(ip, host) => format!("{}\t{}", Ipv4Addr::from(*ip), host),
        NameRecord::Ipv6(ip, host) => format!("{}\t{}", Ipv6Addr::from(*ip), host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_capture() -> CaptureFile {
        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
        cap.section_comments.push("Test capture".to_string());
        cap.name_records
            .push(NameRecord::Ipv4([10, 0, 0, 1], "gateway.local".to_string()));
        cap.decryption_secrets.push(DecryptionSecret {
            secrets_type: 0x544c_534b,
            data: b"CLIENT_RANDOM 01020304 05060708\n".to_vec(),
        });
        let mut frame = Frame::new(
            1,
            Timestamp::from_secs_nanos(1_700_000_000, 123_456_789),
            LinkType::Ethernet,
            vec![0xff; 60],
        );
        frame.comments.push("First packet".to_string());
        frame.flags.direction = PacketDirection::Outbound;
        cap.frames.push(frame);
        cap
    }

    #[test]
    fn roundtrip_pcapng_preserves_metadata_comments_nrb_and_dsb() {
        let orig = sample_capture();
        let bytes = write_pcapng_bytes(&orig).unwrap();
        let parsed = read_capture_bytes(&bytes).unwrap();
        assert_eq!(parsed.format, CaptureFormat::PcapNg);
        assert_eq!(parsed.section_comments, vec!["Test capture"]);
        assert_eq!(parsed.name_records, orig.name_records);
        assert_eq!(parsed.decryption_secrets, orig.decryption_secrets);
        assert_eq!(parsed.frames.len(), 1);
        assert_eq!(parsed.frames[0].timestamp, orig.frames[0].timestamp);
        assert_eq!(parsed.frames[0].comments, vec!["First packet"]);
        assert_eq!(parsed.frames[0].flags.direction, PacketDirection::Outbound);
    }

    #[test]
    fn roundtrip_classic_pcap_micros_and_nanos() {
        let orig = sample_capture();
        let bytes_ns = write_pcap_bytes(&orig, true).unwrap();
        let parsed_ns = read_capture_bytes(&bytes_ns).unwrap();
        assert_eq!(parsed_ns.format, CaptureFormat::PcapNanos);
        assert_eq!(parsed_ns.frames.len(), 1);
        assert_eq!(parsed_ns.frames[0].timestamp, orig.frames[0].timestamp);

        let bytes_us = write_pcap_bytes(&orig, false).unwrap();
        let parsed_us = read_capture_bytes(&bytes_us).unwrap();
        assert_eq!(parsed_us.format, CaptureFormat::PcapMicros);
        assert_eq!(
            parsed_us.frames[0].timestamp,
            Timestamp::from_secs_nanos(1_700_000_000, 123_456_000)
        );
    }

    #[test]
    fn transparent_gzip_and_lz4_decompression() {
        let orig = sample_capture();
        let raw_pcapng = write_pcapng_bytes(&orig).unwrap();

        // Gzip
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&raw_pcapng).unwrap();
        let gz_bytes = gz.finish().unwrap();
        let parsed_gz = read_capture_bytes(&gz_bytes).unwrap();
        assert_eq!(parsed_gz.compression, CompressionFormat::Gzip);
        assert_eq!(parsed_gz.frames.len(), 1);

        // LZ4
        let mut lz4 = lz4_flex::frame::FrameEncoder::new(Vec::new());
        lz4.write_all(&raw_pcapng).unwrap();
        let lz4_bytes = lz4.finish().unwrap();
        let parsed_lz4 = read_capture_bytes(&lz4_bytes).unwrap();
        assert_eq!(parsed_lz4.compression, CompressionFormat::Lz4);
        assert_eq!(parsed_lz4.frames.len(), 1);
    }

    #[test]
    fn truncated_file_recovers_valid_packets_with_warning() {
        let mut orig = sample_capture();
        orig.frames.push(Frame::new(
            2,
            Timestamp::from_secs_nanos(1_700_000_001, 0),
            LinkType::Ethernet,
            vec![0xaa; 64],
        ));
        let mut bytes = write_pcap_bytes(&orig, false).unwrap();
        // Truncate 10 bytes off the end of packet 2
        bytes.truncate(bytes.len() - 10);

        let recovered = read_capture_bytes(&bytes).unwrap();
        assert_eq!(recovered.frames.len(), 1);
        assert!(!recovered.warnings.is_empty());
    }

    #[test]
    fn frame_index_entry_stays_within_memory_budget() {
        assert!(std::mem::size_of::<FrameIndexEntry>() <= 150);
    }
}
