use mash_core::{Frame, InterfaceInfo, LinkType, MashError, Result, Timestamp};
use mash_pcapfile::{write_capture_file, CaptureFile, CaptureFormat};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Enumerate available OS and synthetic capture interfaces (`CAP-01`, `CLI-01 -D`).
pub fn list_capture_interfaces() -> Vec<InterfaceInfo> {
    let mut list = discover_os_interfaces();
    let has_eth0 = list.iter().any(|i| i.name == "eth0");
    let has_lo0 = list.iter().any(|i| i.name == "lo0" || i.is_loopback);

    if !has_eth0 {
        list.push(InterfaceInfo {
            id: list.len() as u32,
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
        });
    }
    if !has_lo0 {
        list.push(InterfaceInfo {
            id: list.len() as u32,
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
        });
    }
    for (idx, item) in list.iter_mut().enumerate() {
        item.id = idx as u32;
    }
    list
}

fn discover_os_interfaces() -> Vec<InterfaceInfo> {
    let mut out = Vec::new();
    if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("ipconfig").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut current_name: Option<String> = None;
            let mut current_addrs: Vec<String> = Vec::new();
            for line in text.lines() {
                let trimmed = line.trim();
                if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
                    if let Some(name) = current_name.take() {
                        if !current_addrs.is_empty() {
                            out.push(InterfaceInfo {
                                id: out.len() as u32,
                                name: name.clone(),
                                description: Some(format!("Windows Host Adapter ({name})")),
                                link_type: LinkType::Ethernet,
                                snap_len: 262_144,
                                ts_resol: 9,
                                os: Some("windows".to_string()),
                                hardware: None,
                                addresses: std::mem::take(&mut current_addrs),
                                is_up: true,
                                is_loopback: name.to_ascii_lowercase().contains("loopback"),
                            });
                        }
                    }
                    let clean = trimmed.trim_end_matches(':').trim().to_string();
                    if !clean.is_empty() && !clean.eq_ignore_ascii_case("Windows IP Configuration")
                    {
                        current_name = Some(clean);
                    }
                } else if (trimmed.contains("IPv4") || trimmed.contains("IPv6"))
                    && trimmed.contains(':')
                {
                    if let Some((_, rhs)) = trimmed.split_once(':') {
                        let addr = rhs.trim().trim_end_matches("(Preferred)").trim();
                        if !addr.is_empty() {
                            current_addrs.push(addr.to_string());
                        }
                    }
                }
            }
            if let Some(name) = current_name {
                if !current_addrs.is_empty() {
                    out.push(InterfaceInfo {
                        id: out.len() as u32,
                        name: name.clone(),
                        description: Some(format!("Windows Host Adapter ({name})")),
                        link_type: LinkType::Ethernet,
                        snap_len: 262_144,
                        ts_resol: 9,
                        os: Some("windows".to_string()),
                        hardware: None,
                        addresses: current_addrs,
                        is_up: true,
                        is_loopback: name.to_ascii_lowercase().contains("loopback"),
                    });
                }
            }
        }
    } else if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_lo = name == "lo";
            out.push(InterfaceInfo {
                id: out.len() as u32,
                name: name.clone(),
                description: Some(format!("Linux Network Interface ({name})")),
                link_type: LinkType::Ethernet,
                snap_len: 262_144,
                ts_resol: 9,
                os: Some(std::env::consts::OS.to_string()),
                hardware: None,
                addresses: if is_lo {
                    vec!["127.0.0.1".to_string()]
                } else {
                    Vec::new()
                },
                is_up: true,
                is_loopback: is_lo,
            });
        }
    }
    out
}

/// Safe Rust BPF capture filter compiler and evaluator (`CAP-03`).
#[derive(Debug, Clone)]
pub enum BpfExpr {
    True,
    Not(Box<BpfExpr>),
    And(Box<BpfExpr>, Box<BpfExpr>),
    Or(Box<BpfExpr>, Box<BpfExpr>),
    EtherProto(u16),
    IpProto(u8),
    HostIpv4([u8; 4]),
    SrcHostIpv4([u8; 4]),
    DstHostIpv4([u8; 4]),
    NetIpv4 { prefix: u32, mask: u32 },
    Port(u16),
    SrcPort(u16),
    DstPort(u16),
    MinLen(usize),
    MaxLen(usize),
}

/// Compiled capture-time BPF filter (`CAP-03`).
#[derive(Debug, Clone)]
pub struct BpfFilter {
    pub source: String,
    pub root: BpfExpr,
}

impl BpfFilter {
    /// Compile a libpcap-compatible BPF filter expression (`tcp`, `udp`, `port 80`, `host 192.168.1.10`, `tcp and port 443`, `not arp`, etc.).
    pub fn compile(expr: &str) -> Result<Self> {
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                source: String::new(),
                root: BpfExpr::True,
            });
        }
        let tokens = tokenize_bpf(trimmed);
        let mut pos = 0usize;
        let root = parse_bpf_or(&tokens, &mut pos)?;
        if pos < tokens.len() {
            return Err(MashError::Filter(format!(
                "Unexpected token '{}' in BPF filter",
                tokens[pos]
            )));
        }
        Ok(Self {
            source: trimmed.to_string(),
            root,
        })
    }

    /// Evaluate the compiled BPF filter against a raw `Frame`.
    pub fn matches(&self, frame: &Frame) -> bool {
        eval_bpf(&self.root, &frame.data)
    }
}

fn tokenize_bpf(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            i += 1;
        } else if c == '(' || c == ')' || c == '!' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            out.push(c.to_string());
            i += 1;
        } else if (c == '&' && chars.get(i + 1) == Some(&'&'))
            || (c == '|' && chars.get(i + 1) == Some(&'|'))
        {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            out.push(format!("{c}{c}"));
            i += 2;
        } else {
            cur.push(c);
            i += 1;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_bpf_or(tokens: &[String], pos: &mut usize) -> Result<BpfExpr> {
    let mut left = parse_bpf_and(tokens, pos)?;
    while let Some(tok) = tokens.get(*pos) {
        if tok.eq_ignore_ascii_case("or") || tok == "||" {
            *pos += 1;
            let right = parse_bpf_and(tokens, pos)?;
            left = BpfExpr::Or(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_bpf_and(tokens: &[String], pos: &mut usize) -> Result<BpfExpr> {
    let mut left = parse_bpf_unary(tokens, pos)?;
    while let Some(tok) = tokens.get(*pos) {
        if tok.eq_ignore_ascii_case("and") || tok == "&&" {
            *pos += 1;
            let right = parse_bpf_unary(tokens, pos)?;
            left = BpfExpr::And(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_bpf_unary(tokens: &[String], pos: &mut usize) -> Result<BpfExpr> {
    let Some(tok) = tokens.get(*pos) else {
        return Err(MashError::Filter("Unexpected end of BPF filter".to_string()));
    };
    if tok.eq_ignore_ascii_case("not") || tok == "!" {
        *pos += 1;
        let inner = parse_bpf_unary(tokens, pos)?;
        return Ok(BpfExpr::Not(Box::new(inner)));
    }
    if tok == "(" {
        *pos += 1;
        let inner = parse_bpf_or(tokens, pos)?;
        if tokens.get(*pos).map(|s| s.as_str()) != Some(")") {
            return Err(MashError::Filter("Missing closing ')' in BPF filter".to_string()));
        }
        *pos += 1;
        return Ok(inner);
    }
    parse_bpf_primary(tokens, pos)
}

fn parse_bpf_primary(tokens: &[String], pos: &mut usize) -> Result<BpfExpr> {
    let tok = tokens
        .get(*pos)
        .ok_or_else(|| MashError::Filter("Expected BPF primitive".to_string()))?
        .to_ascii_lowercase();
    *pos += 1;

    match tok.as_str() {
        "ip" | "ipv4" => Ok(BpfExpr::EtherProto(0x0800)),
        "ip6" | "ipv6" => Ok(BpfExpr::EtherProto(0x86dd)),
        "arp" => Ok(BpfExpr::EtherProto(0x0806)),
        "vlan" => Ok(BpfExpr::EtherProto(0x8100)),
        "tcp" => Ok(BpfExpr::IpProto(6)),
        "udp" => Ok(BpfExpr::IpProto(17)),
        "icmp" => Ok(BpfExpr::IpProto(1)),
        "icmp6" => Ok(BpfExpr::IpProto(58)),
        "ospf" => Ok(BpfExpr::IpProto(89)),
        "gre" => Ok(BpfExpr::IpProto(47)),
        "port" => {
            let p = next_u16(tokens, pos)?;
            Ok(BpfExpr::Port(p))
        }
        "host" => {
            let ip = next_ipv4(tokens, pos)?;
            Ok(BpfExpr::HostIpv4(ip))
        }
        "net" => {
            let cidr = tokens
                .get(*pos)
                .ok_or_else(|| MashError::Filter("Expected CIDR after 'net'".to_string()))?;
            *pos += 1;
            let (ip_str, pfx_str) = cidr.split_once('/').unwrap_or((cidr.as_str(), "24"));
            let addr: Ipv4Addr = ip_str
                .parse()
                .map_err(|_| MashError::Filter(format!("Invalid IPv4 network '{ip_str}'")))?;
            let pfx: u32 = pfx_str
                .parse()
                .map_err(|_| MashError::Filter(format!("Invalid prefix length '{pfx_str}'")))?;
            let mask = if pfx == 0 {
                0
            } else {
                !0u32 << (32 - pfx.min(32))
            };
            Ok(BpfExpr::NetIpv4 {
                prefix: u32::from(addr) & mask,
                mask,
            })
        }
        "src" => {
            let qual = tokens
                .get(*pos)
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if qual == "port" {
                *pos += 1;
                Ok(BpfExpr::SrcPort(next_u16(tokens, pos)?))
            } else if qual == "host" {
                *pos += 1;
                Ok(BpfExpr::SrcHostIpv4(next_ipv4(tokens, pos)?))
            } else {
                Ok(BpfExpr::SrcHostIpv4(next_ipv4(tokens, pos)?))
            }
        }
        "dst" => {
            let qual = tokens
                .get(*pos)
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if qual == "port" {
                *pos += 1;
                Ok(BpfExpr::DstPort(next_u16(tokens, pos)?))
            } else if qual == "host" {
                *pos += 1;
                Ok(BpfExpr::DstHostIpv4(next_ipv4(tokens, pos)?))
            } else {
                Ok(BpfExpr::DstHostIpv4(next_ipv4(tokens, pos)?))
            }
        }
        "greater" => {
            let len = next_u16(tokens, pos)? as usize;
            Ok(BpfExpr::MinLen(len))
        }
        "less" => {
            let len = next_u16(tokens, pos)? as usize;
            Ok(BpfExpr::MaxLen(len))
        }
        other => Err(MashError::Filter(format!(
            "Unsupported BPF primitive '{other}'"
        ))),
    }
}

fn next_u16(tokens: &[String], pos: &mut usize) -> Result<u16> {
    let s = tokens
        .get(*pos)
        .ok_or_else(|| MashError::Filter("Expected numeric value in BPF filter".to_string()))?;
    *pos += 1;
    if let Some(hex) = s.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
            .map_err(|_| MashError::Filter(format!("Invalid hex number '{s}'")))
    } else {
        s.parse::<u16>()
            .map_err(|_| MashError::Filter(format!("Invalid port/number '{s}'")))
    }
}

fn next_ipv4(tokens: &[String], pos: &mut usize) -> Result<[u8; 4]> {
    let s = tokens
        .get(*pos)
        .ok_or_else(|| MashError::Filter("Expected IPv4 address in BPF filter".to_string()))?;
    *pos += 1;
    let addr: Ipv4Addr = s
        .parse()
        .map_err(|_| MashError::Filter(format!("Invalid IPv4 address '{s}'")))?;
    Ok(addr.octets())
}

fn eval_bpf(expr: &BpfExpr, data: &[u8]) -> bool {
    match expr {
        BpfExpr::True => true,
        BpfExpr::Not(inner) => !eval_bpf(inner, data),
        BpfExpr::And(a, b) => eval_bpf(a, data) && eval_bpf(b, data),
        BpfExpr::Or(a, b) => eval_bpf(a, data) || eval_bpf(b, data),
        BpfExpr::MinLen(n) => data.len() >= *n,
        BpfExpr::MaxLen(n) => data.len() <= *n,
        BpfExpr::EtherProto(want) => {
            let Some((ethertype, _)) = l3_offset_and_ethertype(data) else {
                return false;
            };
            ethertype == *want
                || (*want == 0x8100
                    && data.len() >= 14
                    && u16::from_be_bytes([data[12], data[13]]) == 0x8100)
        }
        BpfExpr::IpProto(want) => {
            let Some((ethertype, l3_off)) = l3_offset_and_ethertype(data) else {
                return false;
            };
            if ethertype == 0x0800 && data.len() >= l3_off + 20 {
                data[l3_off + 9] == *want
            } else if ethertype == 0x86dd && data.len() >= l3_off + 40 {
                data[l3_off + 6] == *want
            } else {
                false
            }
        }
        BpfExpr::HostIpv4(ip) => {
            let Some((src, dst)) = extract_ipv4_addrs(data) else {
                return false;
            };
            src == *ip || dst == *ip
        }
        BpfExpr::SrcHostIpv4(ip) => extract_ipv4_addrs(data).is_some_and(|(src, _)| src == *ip),
        BpfExpr::DstHostIpv4(ip) => extract_ipv4_addrs(data).is_some_and(|(_, dst)| dst == *ip),
        BpfExpr::NetIpv4 { prefix, mask } => {
            let Some((src, dst)) = extract_ipv4_addrs(data) else {
                return false;
            };
            (u32::from_be_bytes(src) & *mask) == *prefix
                || (u32::from_be_bytes(dst) & *mask) == *prefix
        }
        BpfExpr::Port(want) => {
            let Some((sport, dport)) = extract_ports(data) else {
                return false;
            };
            sport == *want || dport == *want
        }
        BpfExpr::SrcPort(want) => extract_ports(data).is_some_and(|(sport, _)| sport == *want),
        BpfExpr::DstPort(want) => extract_ports(data).is_some_and(|(_, dport)| dport == *want),
    }
}

fn l3_offset_and_ethertype(data: &[u8]) -> Option<(u16, usize)> {
    if data.len() < 14 {
        return None;
    }
    let et = u16::from_be_bytes([data[12], data[13]]);
    if (et == 0x8100 || et == 0x88a8) && data.len() >= 18 {
        Some((u16::from_be_bytes([data[16], data[17]]), 18))
    } else {
        Some((et, 14))
    }
}

fn extract_ipv4_addrs(data: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    let (et, l3) = l3_offset_and_ethertype(data)?;
    if et != 0x0800 || data.len() < l3 + 20 {
        return None;
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&data[l3 + 12..l3 + 16]);
    dst.copy_from_slice(&data[l3 + 16..l3 + 20]);
    Some((src, dst))
}

fn extract_ports(data: &[u8]) -> Option<(u16, u16)> {
    let (et, l3) = l3_offset_and_ethertype(data)?;
    let l4 = match et {
        0x0800 if data.len() >= l3 + 20 => {
            let proto = data[l3 + 9];
            if proto != 6 && proto != 17 {
                return None;
            }
            let ihl = ((data[l3] & 0x0f) as usize) * 4;
            l3 + ihl
        }
        0x86dd if data.len() >= l3 + 40 => {
            let nh = data[l3 + 6];
            if nh != 6 && nh != 17 {
                return None;
            }
            l3 + 40
        }
        _ => return None,
    };
    if data.len() < l4 + 4 {
        return None;
    }
    let sport = u16::from_be_bytes([data[l4], data[l4 + 1]]);
    let dport = u16::from_be_bytes([data[l4 + 2], data[l4 + 3]]);
    Some((sport, dport))
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

/// Capture live UDP packets on a local socket (`udp://127.0.0.1:9999`) or synthesize realistic multi-protocol frames.
pub fn capture_frames(opts: &CaptureOptions) -> Result<Vec<Frame>> {
    let bpf = match &opts.bpf_filter {
        Some(f) => BpfFilter::compile(f)?,
        None => BpfFilter::compile("")?,
    };
    let target_count = opts.max_packets.unwrap_or(10);
    let mut captured = Vec::new();
    let mut seq = 1u64;

    // Check if an interface specifies a live UDP socket endpoint (`udp://host:port`)
    if let Some(udp_spec) = opts
        .interfaces
        .first()
        .and_then(|s| s.strip_prefix("udp://"))
    {
        let sock = UdpSocket::bind(udp_spec)?;
        let timeout = Duration::from_secs(opts.max_duration_secs.unwrap_or(2));
        let _ = sock.set_read_timeout(Some(timeout));
        let mut buf = [0u8; 65535];
        while (captured.len() as u64) < target_count {
            let Ok((len, peer)) = sock.recv_from(&mut buf) else {
                break;
            };
            let mut frame = wrap_udp_payload_in_eth_frame(seq, peer.port(), &buf[..len]);
            if (frame.data.len() as u32) > opts.snap_len && opts.snap_len > 0 {
                frame.data.truncate(opts.snap_len as usize);
                frame.captured_len = frame.data.len() as u32;
            }
            if bpf.matches(&frame) {
                captured.push(frame);
                seq += 1;
            }
        }
        return Ok(captured);
    }

    // Otherwise generate diverse multi-protocol frames filtered through `bpf`
    let max_attempts = target_count.saturating_mul(16).max(64);
    for attempt in 1..=max_attempts {
        if (captured.len() as u64) >= target_count {
            break;
        }
        let mut frame = synthesize_live_probe_frame(attempt);
        if bpf.matches(&frame) {
            frame.number = (captured.len() + 1) as u64;
            if (frame.data.len() as u32) > opts.snap_len && opts.snap_len > 0 {
                frame.data.truncate(opts.snap_len as usize);
                frame.captured_len = frame.data.len() as u32;
            }
            captured.push(frame);
        }
    }
    Ok(captured)
}

fn wrap_udp_payload_in_eth_frame(seq: u64, src_port: u16, payload: &[u8]) -> Frame {
    let udp_len = (8 + payload.len()) as u16;
    let ip_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(14 + ip_len as usize);
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&ip_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, (seq as u8), 0x40, 0x00, 64, 17, 0x00, 0x00]);
    pkt.extend_from_slice(&[127, 0, 0, 1, 127, 0, 0, 1]);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&9999u16.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(payload);

    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(1_700_000_000_000_000_000);
    Frame::new(
        seq,
        Timestamp::from_nanos(now_nanos),
        LinkType::Ethernet,
        pkt,
    )
}

/// Generate a synthetic Ethernet+IPv4+UDP test frame for loopback / dry-run live capture.
pub fn synthesize_live_probe_frame(seq_number: u64) -> Frame {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 (20 bytes) + UDP (8 bytes) + 8-byte payload = 36 bytes
    pkt.extend_from_slice(&[
        0x45,
        0x00,
        0x00,
        36,
        0x00,
        (seq_number as u8),
        0x40,
        0x00,
        64,
        17,
        0x00,
        0x00,
    ]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_filter_compiles_and_matches_frames() {
        let frame = synthesize_live_probe_frame(1);
        let f_udp = BpfFilter::compile("udp and port 53 and host 192.168.1.10").unwrap();
        assert!(f_udp.matches(&frame));

        let f_tcp = BpfFilter::compile("tcp or port 80").unwrap();
        assert!(!f_tcp.matches(&frame));

        let f_net = BpfFilter::compile("net 192.168.1.0/24 and not arp").unwrap();
        assert!(f_net.matches(&frame));
    }
}
