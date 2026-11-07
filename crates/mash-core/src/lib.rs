pub mod nameres;

pub use nameres::{ip_protocol_name, lookup_oui, lookup_well_known_port, NameResolver, ResolutionConfig};

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Core error type for MUNG-ASH.
#[derive(Debug, Error)]
pub enum MashError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Format error: {0}")]
    Format(String),
    #[error("Dissection error: {0}")]
    Dissect(String),
    #[error("Filter error: {0}")]
    Filter(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Resource limit exceeded: {0}")]
    LimitExceeded(String),
}

pub type Result<T> = std::result::Result<T, MashError>;

/// High-precision packet timestamp in nanoseconds since Unix epoch (1970-01-01T00:00:00Z).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Timestamp {
    pub nanos: i128,
}

impl Timestamp {
    pub const ZERO: Self = Self { nanos: 0 };

    pub const fn from_nanos(nanos: i128) -> Self {
        Self { nanos }
    }

    pub const fn from_micros(micros: i64) -> Self {
        Self {
            nanos: (micros as i128) * 1_000,
        }
    }

    pub const fn from_secs_nanos(secs: u64, subsec_nanos: u32) -> Self {
        Self {
            nanos: (secs as i128) * 1_000_000_000 + (subsec_nanos as i128),
        }
    }

    pub const fn secs(&self) -> i64 {
        (self.nanos / 1_000_000_000) as i64
    }

    pub const fn subsec_nanos(&self) -> u32 {
        (self.nanos.rem_euclid(1_000_000_000)) as u32
    }

    pub const fn subsec_micros(&self) -> u32 {
        self.subsec_nanos() / 1_000
    }

    pub fn as_secs_f64(&self) -> f64 {
        (self.nanos as f64) / 1_000_000_000.0
    }

    pub fn delta_secs_f64(&self, earlier: Timestamp) -> f64 {
        ((self.nanos - earlier.nanos) as f64) / 1_000_000_000.0
    }

    pub fn format_epoch(&self) -> String {
        let s = self.secs();
        let ns = self.subsec_nanos();
        format!("{s}.{ns:09}")
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.secs(), self.subsec_nanos())
    }
}

/// Standard link-layer header types (LINKTYPE_* / DLT_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum LinkType {
    Null,
    #[default]
    Ethernet,
    Ppp,
    RawIp,
    Ieee80211,
    LinuxSll,
    Radiotap,
    Ipv4,
    Ipv6,
    LinuxSll2,
    Unknown(u32),
}

impl LinkType {
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Ethernet,
            9 => Self::Ppp,
            101 => Self::RawIp,
            105 => Self::Ieee80211,
            113 => Self::LinuxSll,
            127 => Self::Radiotap,
            228 => Self::Ipv4,
            229 => Self::Ipv6,
            276 => Self::LinuxSll2,
            other => Self::Unknown(other),
        }
    }

    pub const fn to_u32(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Ethernet => 1,
            Self::Ppp => 9,
            Self::RawIp => 101,
            Self::Ieee80211 => 105,
            Self::LinuxSll => 113,
            Self::Radiotap => 127,
            Self::Ipv4 => 228,
            Self::Ipv6 => 229,
            Self::LinuxSll2 => 276,
            Self::Unknown(v) => v,
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Null => "BSD Loopback / Null",
            Self::Ethernet => "Ethernet",
            Self::Ppp => "Point-to-Point Protocol",
            Self::RawIp => "Raw IP",
            Self::Ieee80211 => "IEEE 802.11 Wireless LAN",
            Self::LinuxSll => "Linux Cooked Capture (SLL)",
            Self::Radiotap => "IEEE 802.11 Radiotap",
            Self::Ipv4 => "Raw IPv4",
            Self::Ipv6 => "Raw IPv6",
            Self::LinuxSll2 => "Linux Cooked Capture v2 (SLL2)",
            Self::Unknown(_) => "Unknown Link Type",
        }
    }
}

/// Capture interface metadata (from live enumeration or pcapng IDB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub link_type: LinkType,
    pub snap_len: u32,
    /// Pcapng `if_tsresol` byte (default 6 = 10^-6 microsecond resolution, 9 = nanosecond).
    pub ts_resol: u8,
    pub os: Option<String>,
    pub hardware: Option<String>,
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        Self {
            id: 0,
            name: "eth0".to_string(),
            description: None,
            link_type: LinkType::Ethernet,
            snap_len: 262_144,
            ts_resol: 9,
            os: None,
            hardware: None,
            addresses: Vec::new(),
            is_up: true,
            is_loopback: false,
        }
    }
}

/// Packet direction metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PacketDirection {
    #[default]
    Unknown,
    Inbound,
    Outbound,
}

/// Per-frame user and capture flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FrameFlags {
    pub marked: bool,
    pub ignored: bool,
    pub time_reference: bool,
    pub direction: PacketDirection,
}

/// Kind of byte buffer backing a dissected layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSourceKind {
    Frame,
    Reassembled,
    Decrypted,
    Decompressed,
    Custom,
}

/// Secondary / derived byte buffer attached to a frame (e.g., decrypted TLS payload, decompressed HTTP body, reassembled IP/TCP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSource {
    pub kind: DataSourceKind,
    pub name: String,
    pub data: Vec<u8>,
}

/// A captured network frame and its metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// 1-based frame number in capture.
    pub number: u64,
    pub timestamp: Timestamp,
    pub captured_len: u32,
    pub orig_len: u32,
    pub link_type: LinkType,
    pub interface_id: u32,
    pub comments: Vec<String>,
    pub flags: FrameFlags,
    pub data: Vec<u8>,
    pub extra_sources: Vec<DataSource>,
}

impl Frame {
    pub fn new(number: u64, timestamp: Timestamp, link_type: LinkType, data: Vec<u8>) -> Self {
        let len = data.len() as u32;
        Self {
            number,
            timestamp,
            captured_len: len,
            orig_len: len,
            link_type,
            interface_id: 0,
            comments: Vec::new(),
            flags: FrameFlags::default(),
            data,
            extra_sources: Vec::new(),
        }
    }

    pub fn add_data_source(&mut self, kind: DataSourceKind, name: impl Into<String>, data: Vec<u8>) -> u8 {
        let idx = (self.extra_sources.len() + 1).min(255) as u8;
        self.extra_sources.push(DataSource {
            kind,
            name: name.into(),
            data,
        });
        idx
    }

    pub fn source_bytes(&self, source_idx: u8) -> Option<&[u8]> {
        if source_idx == 0 {
            Some(&self.data)
        } else {
            self.extra_sources
                .get((source_idx - 1) as usize)
                .map(|s| s.data.as_slice())
        }
    }
}

/// Identifier for a registered protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct ProtocolId(pub u16);

/// Identifier for a registered protocol field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct FieldId(pub u32);

/// Identifier for a node within a packet's `FieldTree`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct NodeId(pub u32);

/// Data type of a registered protocol field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldType {
    /// Protocol or subtree header with no scalar value.
    None,
    Bool,
    Uint8,
    Uint16,
    Uint24,
    Uint32,
    Uint64,
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Ipv4,
    Ipv6,
    MacAddr,
    Bytes,
    String,
    Oid,
    RelativeTime,
    AbsoluteTime,
}

impl FieldType {
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::Uint8
                | Self::Uint16
                | Self::Uint24
                | Self::Uint32
                | Self::Uint64
                | Self::Int8
                | Self::Int16
                | Self::Int32
                | Self::Int64
        )
    }

    pub const fn is_numeric(&self) -> bool {
        self.is_integer() || matches!(self, Self::Float32 | Self::Float64)
    }
}

/// Typed value stored in a `FieldNode`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum FieldValue {
    #[default]
    None,
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Mac([u8; 6]),
    Bytes(Vec<u8>),
    Str(String),
}

impl FieldValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            Self::I64(v) if *v >= 0 => Some(*v as u64),
            Self::Bool(b) => Some(u64::from(*b)),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            Self::U64(v) => i64::try_from(*v).ok(),
            Self::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::F64(v) => Some(*v),
            Self::U64(v) => Some(*v as f64),
            Self::I64(v) => Some(*v as f64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b.as_slice()),
            Self::Ipv4(ip) => Some(ip.as_slice()),
            Self::Ipv6(ip) => Some(ip.as_slice()),
            Self::Mac(mac) => Some(mac.as_slice()),
            Self::Str(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    pub fn value_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Bool(_) => 1,
            Self::U64(_) | Self::I64(_) | Self::F64(_) => 8,
            Self::Ipv4(_) => 4,
            Self::Ipv6(_) => 16,
            Self::Mac(_) => 6,
            Self::Bytes(b) => b.len(),
            Self::Str(s) => s.len(),
        }
    }

    pub fn display_value(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Bool(b) => if *b { "True" } else { "False" }.to_string(),
            Self::U64(v) => v.to_string(),
            Self::I64(v) => v.to_string(),
            Self::F64(v) => format!("{v:.6}"),
            Self::Ipv4(ip) => Ipv4Addr::from(*ip).to_string(),
            Self::Ipv6(ip) => Ipv6Addr::from(*ip).to_string(),
            Self::Mac(m) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            Self::Bytes(b) => b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"),
            Self::Str(s) => s.clone(),
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_value())
    }
}

/// Byte span and optional bitmask in the underlying packet buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ByteRange {
    /// 0 = primary frame buffer, 1+ = derived `DataSource`.
    pub source_idx: u8,
    pub start: usize,
    pub end: usize,
    pub bitmask: Option<u64>,
}

impl ByteRange {
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            source_idx: 0,
            start,
            end,
            bitmask: None,
        }
    }

    pub const fn with_source(source_idx: u8, start: usize, end: usize) -> Self {
        Self {
            source_idx,
            start,
            end,
            bitmask: None,
        }
    }

    pub const fn with_bitmask(mut self, mask: u64) -> Self {
        self.bitmask = Some(mask);
        self
    }

    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub const fn contains_offset(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }
}

/// Expert Information severity levels (STA-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExpertSeverity {
    Chat,
    Note,
    Warn,
    Error,
}

impl ExpertSeverity {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Chat => "Chat",
            Self::Note => "Note",
            Self::Warn => "Warning",
            Self::Error => "Error",
        }
    }
}

/// Expert Information category group (STA-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExpertGroup {
    Checksum,
    Sequence,
    ResponseCode,
    RequestCode,
    Undecoded,
    Reassemble,
    Malformed,
    Protocol,
    Security,
    Comments,
}

impl ExpertGroup {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Checksum => "Checksum",
            Self::Sequence => "Sequence",
            Self::ResponseCode => "Response",
            Self::RequestCode => "Request",
            Self::Undecoded => "Undecoded",
            Self::Reassemble => "Reassemble",
            Self::Malformed => "Malformed",
            Self::Protocol => "Protocol",
            Self::Security => "Security",
            Self::Comments => "Comments",
        }
    }
}

/// A diagnostic or protocol anomaly item attached to a field or frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpertItem {
    pub severity: ExpertSeverity,
    pub group: ExpertGroup,
    pub protocol: String,
    pub summary: String,
    pub byte_range: ByteRange,
}

/// A node in the hierarchical dissected field tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldNode {
    pub id: NodeId,
    pub field_id: FieldId,
    pub protocol_id: ProtocolId,
    pub abbrev: String,
    pub name: String,
    pub label: String,
    pub field_type: FieldType,
    pub value: FieldValue,
    pub byte_range: ByteRange,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub expert: Option<ExpertItem>,
    /// True if synthesized by MUNG-ASH (e.g. `[Stream index: 0]`) rather than read directly from wire bytes.
    pub generated: bool,
}

/// Arena-allocated hierarchical field tree for a dissected packet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FieldTree {
    pub nodes: Vec<FieldNode>,
    pub roots: Vec<NodeId>,
    pub experts: Vec<ExpertItem>,
    /// Ordered list of protocol filter names dissected in this frame (e.g. `["eth", "ip", "tcp", "http"]`).
    pub protocols_in_frame: Vec<String>,
}

impl FieldTree {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_node(
        &mut self,
        parent: Option<NodeId>,
        field_id: FieldId,
        protocol_id: ProtocolId,
        abbrev: impl Into<String>,
        name: impl Into<String>,
        label: impl Into<String>,
        field_type: FieldType,
        value: FieldValue,
        byte_range: ByteRange,
        generated: bool,
    ) -> NodeId {
        let id = NodeId(self.nodes.len() as u32);
        let node = FieldNode {
            id,
            field_id,
            protocol_id,
            abbrev: abbrev.into(),
            name: name.into(),
            label: label.into(),
            field_type,
            value,
            byte_range,
            parent,
            children: Vec::new(),
            expert: None,
            generated,
        };
        self.nodes.push(node);
        if let Some(pid) = parent {
            if let Some(pnode) = self.nodes.get_mut(pid.0 as usize) {
                pnode.children.push(id);
            }
        } else {
            self.roots.push(id);
        }
        id
    }

    pub fn attach_expert(&mut self, node_id: NodeId, expert: ExpertItem) {
        if let Some(node) = self.nodes.get_mut(node_id.0 as usize) {
            node.expert = Some(expert.clone());
        }
        self.experts.push(expert);
    }

    pub fn add_protocol_in_frame(&mut self, proto_abbrev: impl Into<String>) {
        let s = proto_abbrev.into();
        if self.protocols_in_frame.last() != Some(&s) {
            self.protocols_in_frame.push(s);
        }
    }

    pub fn node(&self, id: NodeId) -> Option<&FieldNode> {
        self.nodes.get(id.0 as usize)
    }

    pub fn node_mut(&mut self, id: NodeId) -> Option<&mut FieldNode> {
        self.nodes.get_mut(id.0 as usize)
    }

    /// Find all field nodes matching the given abbreviation (e.g., `"ip.src"`).
    pub fn by_abbrev<'a, 'b>(&'a self, abbrev: &'b str) -> impl Iterator<Item = &'a FieldNode> + use<'a, 'b> {
        self.nodes.iter().filter(move |n| n.abbrev == abbrev)
    }

    /// Return the N-th occurrence (1-based, like `ip.src#2` in display filters) of a field.
    pub fn by_abbrev_layer(&self, abbrev: &str, layer_1based: usize) -> Option<&FieldNode> {
        if layer_1based == 0 {
            return None;
        }
        self.by_abbrev(abbrev).nth(layer_1based - 1)
    }

    /// Check whether a protocol or field abbreviation is present anywhere in this packet.
    pub fn has_field_or_protocol(&self, abbrev: &str) -> bool {
        self.protocols_in_frame.iter().any(|p| p == abbrev)
            || self.nodes.iter().any(|n| n.abbrev == abbrev)
    }

    /// Find the deepest field node covering a byte offset in `source_idx`.
    pub fn deepest_node_at_offset(&self, source_idx: u8, offset: usize) -> Option<&FieldNode> {
        let mut best: Option<&FieldNode> = None;
        for node in &self.nodes {
            if !node.generated
                && node.byte_range.source_idx == source_idx
                && node.byte_range.contains_offset(offset)
            {
                match best {
                    None => best = Some(node),
                    Some(prev) if node.byte_range.len() <= prev.byte_range.len() => {
                        best = Some(node);
                    }
                    _ => {}
                }
            }
        }
        best
    }

    /// Maximum expert severity present in this tree.
    pub fn max_expert_severity(&self) -> Option<ExpertSeverity> {
        self.experts.iter().map(|e| e.severity).max()
    }
}

/// Summary row for a dissected packet (displayed in Packet List and CLI summary output).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketSummary {
    pub number: u64,
    pub timestamp: Timestamp,
    pub rel_time_sec: f64,
    pub delta_time_sec: f64,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: u32,
    pub info: String,
    pub max_expert: Option<ExpertSeverity>,
}

impl Default for PacketSummary {
    fn default() -> Self {
        Self {
            number: 1,
            timestamp: Timestamp::ZERO,
            rel_time_sec: 0.0,
            delta_time_sec: 0.0,
            source: String::new(),
            destination: String::new(),
            protocol: "Frame".to_string(),
            length: 0,
            info: String::new(),
            max_expert: None,
        }
    }
}

/// Complete dissected result for a single frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DissectedPacket {
    pub summary: PacketSummary,
    pub tree: FieldTree,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_conversions_and_delta() {
        let t1 = Timestamp::from_secs_nanos(1_700_000_000, 100_000_000);
        let t2 = Timestamp::from_secs_nanos(1_700_000_001, 600_000_000);
        assert_eq!(t1.secs(), 1_700_000_000);
        assert_eq!(t1.subsec_nanos(), 100_000_000);
        assert_eq!(t1.subsec_micros(), 100_000);
        let delta = t2.delta_secs_f64(t1);
        assert!((delta - 1.5).abs() < 1e-9);
    }

    #[test]
    fn field_tree_hierarchy_and_lookup() {
        let mut tree = FieldTree::new();
        tree.add_protocol_in_frame("eth");
        tree.add_protocol_in_frame("ip");
        let root = tree.add_node(
            None,
            FieldId(1),
            ProtocolId(1),
            "ip",
            "Internet Protocol Version 4",
            "Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2",
            FieldType::None,
            FieldValue::None,
            ByteRange::new(14, 34),
            false,
        );
        let src_node = tree.add_node(
            Some(root),
            FieldId(2),
            ProtocolId(1),
            "ip.src",
            "Source Address",
            "Source Address: 10.0.0.1",
            FieldType::Ipv4,
            FieldValue::Ipv4([10, 0, 0, 1]),
            ByteRange::new(26, 30),
            false,
        );
        assert_eq!(tree.roots, vec![root]);
        assert_eq!(tree.node(root).unwrap().children, vec![src_node]);
        let found: Vec<_> = tree.by_abbrev("ip.src").collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value.display_value(), "10.0.0.1");
        assert_eq!(
            tree.deepest_node_at_offset(0, 27).map(|n| n.id),
            Some(src_node)
        );
    }

    #[test]
    fn name_resolver_formats_mac_ip_and_ports() {
        let mut nr = NameResolver::new(ResolutionConfig {
            resolve_mac: true,
            resolve_network: true,
            resolve_transport: true,
            use_captured_dns: true,
        });
        assert_eq!(nr.format_mac([0xff; 6]), "Broadcast");
        assert_eq!(nr.format_mac([0x08, 0x00, 0x27, 0x12, 0x34, 0x56]), "VBox_12:34:56");
        nr.learn_dns_v4([93, 184, 216, 34], "example.com");
        assert_eq!(nr.format_ipv4([93, 184, 216, 34]), "example.com");
        assert_eq!(nr.tcp_service_name(443), Some("https"));
        assert_eq!(nr.udp_service_name(53), Some("domain"));
    }
}
