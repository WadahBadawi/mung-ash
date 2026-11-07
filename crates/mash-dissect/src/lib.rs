use mash_core::{
    ByteRange, DissectedPacket, ExpertGroup, ExpertItem, ExpertSeverity, FieldId, FieldTree,
    FieldType, FieldValue, Frame, MashError, NameResolver, NodeId, PacketSummary, ProtocolId,
    Result, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// Maximum tunnel/encapsulation recursion depth per packet (REL-03).
pub const MAX_RECURSION_DEPTH: usize = 32;

/// Metadata for a registered protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolMeta {
    pub id: ProtocolId,
    /// Full display name, e.g., `"Transmission Control Protocol"`.
    pub name: String,
    /// Short column name, e.g., `"TCP"`.
    pub short_name: String,
    /// Filter abbreviation, e.g., `"tcp"`.
    pub filter_name: String,
}

/// Metadata for a registered protocol field (`DIS-02`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldMeta {
    pub id: FieldId,
    pub protocol_id: ProtocolId,
    /// Dotted filter abbreviation, e.g., `"tcp.srcport"`.
    pub abbrev: String,
    /// Human-readable field name, e.g., `"Source Port"`.
    pub name: String,
    pub field_type: FieldType,
    pub description: String,
}

/// Central registry of all protocols and fields (`DIS-02`).
#[derive(Debug, Clone, Default)]
pub struct Registry {
    protocols: Vec<ProtocolMeta>,
    proto_by_filter: HashMap<String, ProtocolId>,
    fields: Vec<FieldMeta>,
    field_by_abbrev: HashMap<String, FieldId>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a protocol. Rejects duplicate filter names.
    pub fn register_protocol(
        &mut self,
        name: impl Into<String>,
        short_name: impl Into<String>,
        filter_name: impl Into<String>,
    ) -> Result<ProtocolId> {
        let filter_name = filter_name.into();
        if let Some(&existing) = self.proto_by_filter.get(&filter_name) {
            return Ok(existing);
        }
        let id = ProtocolId(self.protocols.len() as u16);
        let meta = ProtocolMeta {
            id,
            name: name.into(),
            short_name: short_name.into(),
            filter_name: filter_name.clone(),
        };
        self.protocols.push(meta);
        self.proto_by_filter.insert(filter_name.clone(), id);

        // Also register the protocol itself as a `FieldType::None` entry so filter expressions like `tcp` or `dns` resolve cleanly.
        let _ = self.register_field(
            id,
            filter_name,
            self.protocols[id.0 as usize].name.clone(),
            FieldType::None,
            "Protocol presence filter",
        );

        Ok(id)
    }

    /// Register a field under a protocol. Rejects duplicate field abbreviations with a different type.
    pub fn register_field(
        &mut self,
        protocol_id: ProtocolId,
        abbrev: impl Into<String>,
        name: impl Into<String>,
        field_type: FieldType,
        description: impl Into<String>,
    ) -> Result<FieldId> {
        let abbrev = abbrev.into();
        if let Some(&existing_id) = self.field_by_abbrev.get(&abbrev) {
            let existing = &self.fields[existing_id.0 as usize];
            if existing.field_type != field_type && existing.field_type != FieldType::None {
                return Err(MashError::Dissect(format!(
                    "Duplicate field abbreviation '{abbrev}' registered with conflicting types ({:?} vs {:?})",
                    existing.field_type, field_type
                )));
            }
            return Ok(existing_id);
        }
        let id = FieldId(self.fields.len() as u32);
        let meta = FieldMeta {
            id,
            protocol_id,
            abbrev: abbrev.clone(),
            name: name.into(),
            field_type,
            description: description.into(),
        };
        self.fields.push(meta);
        self.field_by_abbrev.insert(abbrev, id);
        Ok(id)
    }

    pub fn protocol(&self, id: ProtocolId) -> Option<&ProtocolMeta> {
        self.protocols.get(id.0 as usize)
    }

    pub fn protocol_by_filter(&self, filter_name: &str) -> Option<&ProtocolMeta> {
        let id = self.proto_by_filter.get(filter_name)?;
        self.protocol(*id)
    }

    pub fn field(&self, id: FieldId) -> Option<&FieldMeta> {
        self.fields.get(id.0 as usize)
    }

    pub fn field_by_abbrev(&self, abbrev: &str) -> Option<&FieldMeta> {
        let id = self.field_by_abbrev.get(abbrev)?;
        self.field(*id)
    }

    pub fn protocols(&self) -> &[ProtocolMeta] {
        &self.protocols
    }

    pub fn fields(&self) -> &[FieldMeta] {
        &self.fields
    }

    /// Return up to `max_results` closest field/protocol abbreviations by edit distance (`FLT-07`).
    pub fn did_you_mean(&self, query: &str, max_results: usize) -> Vec<String> {
        let mut candidates: Vec<(usize, &str)> = self
            .fields
            .iter()
            .map(|f| (levenshtein(query, &f.abbrev), f.abbrev.as_str()))
            .filter(|(dist, _)| *dist <= 4)
            .collect();
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
        candidates
            .into_iter()
            .take(max_results)
            .map(|(_, s)| s.to_string())
            .collect()
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a_chars[i - 1] != b_chars[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Error returned by `PacketCursor` when a packet is shorter than required by the protocol specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TruncatedError {
    pub offset: usize,
    pub needed: usize,
    pub available: usize,
}

/// Bounds-checked slice cursor over a packet or derived data source (`DIS-04`, `REL-01`).
#[derive(Debug, Clone)]
pub struct PacketCursor<'a> {
    data: &'a [u8],
    base_offset: usize,
    pos: usize,
    source_idx: u8,
}

impl<'a> PacketCursor<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            base_offset: 0,
            pos: 0,
            source_idx: 0,
        }
    }

    pub const fn with_source(data: &'a [u8], source_idx: u8, base_offset: usize) -> Self {
        Self {
            data,
            base_offset,
            pos: 0,
            source_idx,
        }
    }

    pub const fn source_idx(&self) -> u8 {
        self.source_idx
    }

    pub const fn position(&self) -> usize {
        self.pos
    }

    pub const fn abs_offset(&self) -> usize {
        self.base_offset + self.pos
    }

    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn full_slice(&self) -> &'a [u8] {
        self.data
    }

    pub fn slice_remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    pub fn range_from(&self, start_abs: usize) -> ByteRange {
        ByteRange::with_source(self.source_idx, start_abs, self.abs_offset())
    }

    pub fn remaining_range(&self) -> ByteRange {
        ByteRange::with_source(
            self.source_idx,
            self.abs_offset(),
            self.base_offset + self.data.len(),
        )
    }

    pub fn peek_bytes(&self, len: usize) -> std::result::Result<&'a [u8], TruncatedError> {
        if self.remaining() < len {
            return Err(TruncatedError {
                offset: self.abs_offset(),
                needed: len,
                available: self.remaining(),
            });
        }
        Ok(&self.data[self.pos..self.pos + len])
    }

    pub fn peek_u8(&self) -> std::result::Result<u8, TruncatedError> {
        Ok(self.peek_bytes(1)?[0])
    }

    pub fn read_bytes(
        &mut self,
        len: usize,
    ) -> std::result::Result<(&'a [u8], ByteRange), TruncatedError> {
        let slice = self.peek_bytes(len)?;
        let start = self.abs_offset();
        self.pos += len;
        let end = self.abs_offset();
        Ok((slice, ByteRange::with_source(self.source_idx, start, end)))
    }

    pub fn read_u8(&mut self) -> std::result::Result<(u8, ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(1)?;
        Ok((b[0], r))
    }

    pub fn read_u16_be(&mut self) -> std::result::Result<(u16, ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(2)?;
        Ok((u16::from_be_bytes([b[0], b[1]]), r))
    }

    pub fn read_u16_le(&mut self) -> std::result::Result<(u16, ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(2)?;
        Ok((u16::from_le_bytes([b[0], b[1]]), r))
    }

    pub fn read_u24_be(&mut self) -> std::result::Result<(u32, ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(3)?;
        Ok((u32::from_be_bytes([0, b[0], b[1], b[2]]), r))
    }

    pub fn read_u32_be(&mut self) -> std::result::Result<(u32, ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(4)?;
        Ok((u32::from_be_bytes([b[0], b[1], b[2], b[3]]), r))
    }

    pub fn read_u32_le(&mut self) -> std::result::Result<(u32, ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(4)?;
        Ok((u32::from_le_bytes([b[0], b[1], b[2], b[3]]), r))
    }

    pub fn read_u64_be(&mut self) -> std::result::Result<(u64, ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(8)?;
        Ok((
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            r,
        ))
    }

    pub fn read_ipv4(&mut self) -> std::result::Result<([u8; 4], ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(4)?;
        Ok(([b[0], b[1], b[2], b[3]], r))
    }

    pub fn read_ipv6(&mut self) -> std::result::Result<([u8; 16], ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        Ok((arr, r))
    }

    pub fn read_mac(&mut self) -> std::result::Result<([u8; 6], ByteRange), TruncatedError> {
        let (b, r) = self.read_bytes(6)?;
        Ok(([b[0], b[1], b[2], b[3], b[4], b[5]], r))
    }

    /// Create a bounded sub-cursor for a payload of `len` bytes and advance `self` past it.
    pub fn sub_cursor(
        &mut self,
        len: usize,
    ) -> std::result::Result<PacketCursor<'a>, TruncatedError> {
        let actual = len.min(self.remaining());
        let start = self.abs_offset();
        let slice = &self.data[self.pos..self.pos + actual];
        self.pos += actual;
        Ok(PacketCursor {
            data: slice,
            base_offset: start,
            pos: 0,
            source_idx: self.source_idx,
        })
    }

    pub fn advance(&mut self, len: usize) -> std::result::Result<ByteRange, TruncatedError> {
        let (_, r) = self.read_bytes(len)?;
        Ok(r)
    }
}

/// Dispatch table selector (`DIS-03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TableId {
    LinkType,
    EtherType,
    IpProto,
    TcpPort,
    UdpPort,
}

impl TableId {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LinkType => "wtap_encap",
            Self::EtherType => "ethertype",
            Self::IpProto => "ip.proto",
            Self::TcpPort => "tcp.port",
            Self::UdpPort => "udp.port",
        }
    }

    pub fn from_selector_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "link_type" | "wtap_encap" => Some(Self::LinkType),
            "ethertype" | "eth.type" => Some(Self::EtherType),
            "ip.proto" => Some(Self::IpProto),
            "tcp.port" => Some(Self::TcpPort),
            "udp.port" => Some(Self::UdpPort),
            _ => None,
        }
    }
}

/// Action returned by a dissector indicating how the remaining payload should be processed (`DIS-03`, `DIS-06`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// No further payload dissection.
    None,
    /// Dispatch via a registered selector table (`ethertype`, `ip.proto`, etc.).
    Table(TableId, u32),
    /// Dispatch via transport ports (`tcp.port` or `udp.port`), consulting Decode-As, destination/source port registrations, and heuristic dissectors.
    Ports {
        table: TableId,
        src_port: u16,
        dst_port: u16,
    },
    /// Directly invoke a specific protocol dissector.
    Dissector(ProtocolId),
    /// Signal that the current PDU is incomplete and requires additional bytes from stream reassembly (`DIS-06`).
    NeedMore { needed: Option<usize> },
}

/// Result of running a single protocol dissector.
pub type DissectResult = std::result::Result<Next, TruncatedError>;

/// Core trait implemented by every protocol dissector (`DIS-01`).
pub trait Dissector: Send + Sync {
    fn protocol(&self) -> ProtocolId;
    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult;
    fn heuristic_probe(&self, _buf: &[u8], _ctx: &DissectCtx<'_>) -> bool {
        false
    }
}

/// Runtime "Decode As" override table (`DIS-03`).
#[derive(Debug, Clone, Default)]
pub struct DecodeAsTable {
    overrides: HashMap<(TableId, u32), String>,
}

impl DecodeAsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, table: TableId, key: u32, proto_filter_name: impl Into<String>) {
        self.overrides.insert((table, key), proto_filter_name.into());
    }

    pub fn remove(&mut self, table: TableId, key: u32) {
        self.overrides.remove(&(table, key));
    }

    pub fn get(&self, table: TableId, key: u32) -> Option<&str> {
        self.overrides.get(&(table, key)).map(|s| s.as_str())
    }

    pub fn entries(&self) -> impl Iterator<Item = (&(TableId, u32), &String)> {
        self.overrides.iter()
    }

    /// Parse a CLI Decode-As specification such as `"tcp.port==8443,http"` or `"ethertype==0x88b5,dns"`.
    pub fn parse_and_insert(&mut self, spec: &str) -> Result<()> {
        let (selector_part, proto_part) = spec.split_once(',').ok_or_else(|| {
            MashError::Dissect(format!(
                "Invalid Decode-As spec '{spec}': expected '<table==value>,<protocol>'"
            ))
        })?;
        let (table_name, val_str) = selector_part
            .split_once("==")
            .or_else(|| selector_part.split_once('='))
            .ok_or_else(|| {
                MashError::Dissect(format!(
                    "Invalid Decode-As selector '{selector_part}': expected '=='"
                ))
            })?;
        let table = TableId::from_selector_name(table_name).ok_or_else(|| {
            MashError::Dissect(format!("Unknown Decode-As table '{table_name}'"))
        })?;
        let val_trimmed = val_str.trim();
        let key = if let Some(hex) = val_trimmed
            .strip_prefix("0x")
            .or_else(|| val_trimmed.strip_prefix("0X"))
        {
            u32::from_str_radix(hex, 16)
        } else {
            val_trimmed.parse::<u32>()
        }
        .map_err(|_| MashError::Dissect(format!("Invalid Decode-As key '{val_trimmed}'")))?;

        self.insert(table, key, proto_part.trim().to_ascii_lowercase());
        Ok(())
    }
}

/// Canonical bidirectional conversation key for stream indexing (`DIS-07`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalFlowKey {
    pub proto: u8,
    pub ep_a: (String, u16),
    pub ep_b: (String, u16),
}

impl CanonicalFlowKey {
    pub fn new(proto: u8, src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Self {
        let a = (src_ip.to_string(), src_port);
        let b = (dst_ip.to_string(), dst_port);
        if a <= b {
            Self {
                proto,
                ep_a: a,
                ep_b: b,
            }
        } else {
            Self {
                proto,
                ep_a: b,
                ep_b: a,
            }
        }
    }
}

/// Request metadata stored for correlating responses (`DIS-07`).
#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub frame_number: u64,
    pub timestamp: Timestamp,
    pub summary: String,
}

/// Stateful conversation & request/response tracker across a capture session (`DIS-07`).
#[derive(Debug, Clone, Default)]
pub struct ConversationTracker {
    tcp_streams: HashMap<CanonicalFlowKey, u32>,
    udp_streams: HashMap<CanonicalFlowKey, u32>,
    dns_requests: HashMap<(u32, u16), RequestRecord>,
    icmp_requests: HashMap<(String, String, u16, u16), RequestRecord>,
    http_requests: HashMap<u32, RequestRecord>,
    /// Paired correlations: `response_frame -> (request_frame, rtt_seconds)`
    paired_responses: HashMap<u64, (u64, f64)>,
    /// Forward correlations: `request_frame -> response_frame`
    paired_requests: HashMap<u64, u64>,
}

impl ConversationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tcp_stream_index(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> u32 {
        let key = CanonicalFlowKey::new(6, src_ip, src_port, dst_ip, dst_port);
        let next_id = self.tcp_streams.len() as u32;
        *self.tcp_streams.entry(key).or_insert(next_id)
    }

    pub fn udp_stream_index(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> u32 {
        let key = CanonicalFlowKey::new(17, src_ip, src_port, dst_ip, dst_port);
        let next_id = self.udp_streams.len() as u32;
        *self.udp_streams.entry(key).or_insert(next_id)
    }

    pub fn record_dns_query(
        &mut self,
        stream_id: u32,
        txid: u16,
        frame_number: u64,
        timestamp: Timestamp,
        qname: String,
    ) {
        self.dns_requests.insert(
            (stream_id, txid),
            RequestRecord {
                frame_number,
                timestamp,
                summary: qname,
            },
        );
    }

    pub fn match_dns_response(
        &mut self,
        stream_id: u32,
        txid: u16,
        resp_frame: u64,
        resp_ts: Timestamp,
    ) -> Option<(u64, f64)> {
        if let Some(&existing) = self.paired_responses.get(&resp_frame) {
            return Some(existing);
        }
        let req = self.dns_requests.get(&(stream_id, txid))?;
        if req.frame_number >= resp_frame {
            return None;
        }
        let rtt = resp_ts.delta_secs_f64(req.timestamp).max(0.0);
        let req_num = req.frame_number;
        self.paired_responses.insert(resp_frame, (req_num, rtt));
        self.paired_requests.insert(req_num, resp_frame);
        Some((req_num, rtt))
    }

    pub fn record_icmp_echo_request(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        id: u16,
        seq: u16,
        frame_number: u64,
        timestamp: Timestamp,
    ) {
        self.icmp_requests.insert(
            (src_ip.to_string(), dst_ip.to_string(), id, seq),
            RequestRecord {
                frame_number,
                timestamp,
                summary: format!("id={id} seq={seq}"),
            },
        );
    }

    pub fn match_icmp_echo_reply(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        id: u16,
        seq: u16,
        resp_frame: u64,
        resp_ts: Timestamp,
    ) -> Option<(u64, f64)> {
        if let Some(&existing) = self.paired_responses.get(&resp_frame) {
            return Some(existing);
        }
        // Reply has swapped src/dst relative to the echo request
        let req = self
            .icmp_requests
            .get(&(dst_ip.to_string(), src_ip.to_string(), id, seq))?;
        if req.frame_number >= resp_frame {
            return None;
        }
        let rtt = resp_ts.delta_secs_f64(req.timestamp).max(0.0);
        let req_num = req.frame_number;
        self.paired_responses.insert(resp_frame, (req_num, rtt));
        self.paired_requests.insert(req_num, resp_frame);
        Some((req_num, rtt))
    }

    pub fn record_http_request(
        &mut self,
        tcp_stream: u32,
        frame_number: u64,
        timestamp: Timestamp,
        uri: String,
    ) {
        self.http_requests.insert(
            tcp_stream,
            RequestRecord {
                frame_number,
                timestamp,
                summary: uri,
            },
        );
    }

    pub fn match_http_response(
        &mut self,
        tcp_stream: u32,
        resp_frame: u64,
        resp_ts: Timestamp,
    ) -> Option<(u64, f64, String)> {
        let req = self.http_requests.get(&tcp_stream)?;
        if req.frame_number >= resp_frame {
            return None;
        }
        let rtt = resp_ts.delta_secs_f64(req.timestamp).max(0.0);
        let req_num = req.frame_number;
        let uri = req.summary.clone();
        self.paired_responses.insert(resp_frame, (req_num, rtt));
        self.paired_requests.insert(req_num, resp_frame);
        Some((req_num, rtt, uri))
    }

    pub fn response_for_request(&self, req_frame: u64) -> Option<u64> {
        self.paired_requests.get(&req_frame).copied()
    }
}

/// Mutable context passed through the dissector pipeline for a single packet.
pub struct DissectCtx<'a> {
    pub frame: &'a Frame,
    pub registry: &'a Registry,
    pub resolver: &'a mut NameResolver,
    pub conversations: &'a mut ConversationTracker,
    pub summary: PacketSummary,
    pub tree: FieldTree,
    pub depth: usize,
    pub current_proto: ProtocolId,
    /// Raw (un-resolved) network source address string for conversation tracking.
    pub net_src_raw: Option<String>,
    /// Raw (un-resolved) network destination address string for conversation tracking.
    pub net_dst_raw: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub stream_id: Option<u32>,
}

impl<'a> DissectCtx<'a> {
    pub fn set_protocol_column(&mut self, short_name: impl Into<String>) {
        self.summary.protocol = short_name.into();
    }

    pub fn set_info(&mut self, info: impl Into<String>) {
        self.summary.info = info.into();
    }

    pub fn append_info(&mut self, extra: &str) {
        if self.summary.info.is_empty() {
            self.summary.info = extra.to_string();
        } else {
            self.summary.info.push_str(extra);
        }
    }

    /// Begin a top-level protocol subtree node in the `FieldTree`.
    pub fn begin_protocol(
        &mut self,
        proto_id: ProtocolId,
        label: impl Into<String>,
        byte_range: ByteRange,
    ) -> NodeId {
        self.current_proto = proto_id;
        let (abbrev, name, short) = if let Some(meta) = self.registry.protocol(proto_id) {
            (
                meta.filter_name.clone(),
                meta.name.clone(),
                meta.short_name.clone(),
            )
        } else {
            (
                "unknown".to_string(),
                "Unknown Protocol".to_string(),
                "UNKNOWN".to_string(),
            )
        };
        self.tree.add_protocol_in_frame(abbrev.clone());
        self.summary.protocol = short;
        let field_id = self
            .registry
            .field_by_abbrev(&abbrev)
            .map(|f| f.id)
            .unwrap_or(FieldId(0));
        self.tree.add_node(
            None,
            field_id,
            proto_id,
            abbrev,
            name,
            label,
            FieldType::None,
            FieldValue::None,
            byte_range,
            false,
        )
    }

    /// Update the byte range and/or label of an existing node (e.g., when a protocol header finishes parsing).
    pub fn update_node_range(&mut self, node_id: NodeId, range: ByteRange) {
        if let Some(node) = self.tree.node_mut(node_id) {
            node.byte_range = range;
        }
    }

    pub fn update_node_label(&mut self, node_id: NodeId, label: impl Into<String>) {
        if let Some(node) = self.tree.node_mut(node_id) {
            node.label = label.into();
        }
    }

    /// Add a field by its registered abbreviation under `parent`.
    pub fn add_field(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        value: FieldValue,
        byte_range: ByteRange,
        custom_label: Option<String>,
        generated: bool,
    ) -> NodeId {
        let (field_id, proto_id, name, field_type) =
            if let Some(meta) = self.registry.field_by_abbrev(abbrev) {
                (meta.id, meta.protocol_id, meta.name.clone(), meta.field_type)
            } else {
                let inferred_type = match &value {
                    FieldValue::None => FieldType::None,
                    FieldValue::Bool(_) => FieldType::Bool,
                    FieldValue::U64(_) => FieldType::Uint64,
                    FieldValue::I64(_) => FieldType::Int64,
                    FieldValue::F64(_) => FieldType::Float64,
                    FieldValue::Ipv4(_) => FieldType::Ipv4,
                    FieldValue::Ipv6(_) => FieldType::Ipv6,
                    FieldValue::Mac(_) => FieldType::MacAddr,
                    FieldValue::Bytes(_) => FieldType::Bytes,
                    FieldValue::Str(_) => FieldType::String,
                };
                (
                    FieldId(0),
                    self.current_proto,
                    abbrev.to_string(),
                    inferred_type,
                )
            };

        let label = custom_label.unwrap_or_else(|| {
            if value == FieldValue::None {
                name.clone()
            } else if generated {
                format!("[{}: {}]", name, value.display_value())
            } else {
                format!("{}: {}", name, value.display_value())
            }
        });

        self.tree.add_node(
            parent,
            field_id,
            proto_id,
            abbrev.to_string(),
            name,
            label,
            field_type,
            value,
            byte_range,
            generated,
        )
    }

    pub fn add_u64(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        val: u64,
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::U64(val), range, label, false)
    }

    pub fn add_bool(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        val: bool,
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::Bool(val), range, label, false)
    }

    pub fn add_str(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        val: impl Into<String>,
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(
            parent,
            abbrev,
            FieldValue::Str(val.into()),
            range,
            label,
            false,
        )
    }

    pub fn add_bytes(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        val: Vec<u8>,
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::Bytes(val), range, label, false)
    }

    pub fn add_ipv4(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        ip: [u8; 4],
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::Ipv4(ip), range, label, false)
    }

    pub fn add_ipv6(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        ip: [u8; 16],
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::Ipv6(ip), range, label, false)
    }

    pub fn add_mac(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        mac: [u8; 6],
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::Mac(mac), range, label, false)
    }

    pub fn add_generated_u64(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        val: u64,
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::U64(val), range, label, true)
    }

    pub fn add_generated_f64(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        val: f64,
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(parent, abbrev, FieldValue::F64(val), range, label, true)
    }

    pub fn add_generated_str(
        &mut self,
        parent: Option<NodeId>,
        abbrev: &str,
        val: impl Into<String>,
        range: ByteRange,
        label: Option<String>,
    ) -> NodeId {
        self.add_field(
            parent,
            abbrev,
            FieldValue::Str(val.into()),
            range,
            label,
            true,
        )
    }

    /// Attach an Expert Info item to `node_id` and update the packet's max expert severity (`STA-05`).
    pub fn add_expert(
        &mut self,
        node_id: NodeId,
        severity: ExpertSeverity,
        group: ExpertGroup,
        summary: impl Into<String>,
        byte_range: ByteRange,
    ) {
        let proto_short = self
            .registry
            .protocol(self.current_proto)
            .map(|p| p.short_name.clone())
            .unwrap_or_else(|| self.summary.protocol.clone());
        let item = ExpertItem {
            severity,
            group,
            protocol: proto_short,
            summary: summary.into(),
            byte_range,
        };
        self.tree.attach_expert(node_id, item);
        self.summary.max_expert = self.tree.max_expert_severity();
    }
}

/// Dissector engine managing protocol registration, selector tables, Decode-As overrides, and safe packet dissection.
pub struct DissectorEngine {
    pub registry: Registry,
    dissectors: HashMap<ProtocolId, Arc<dyn Dissector>>,
    tables: HashMap<(TableId, u32), ProtocolId>,
    tcp_heuristics: Vec<ProtocolId>,
    udp_heuristics: Vec<ProtocolId>,
    pub decode_as: DecodeAsTable,
    frame_proto_id: ProtocolId,
    data_proto_id: ProtocolId,
}

impl Default for DissectorEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DissectorEngine {
    pub fn new() -> Self {
        let mut registry = Registry::new();
        let frame_proto_id = registry
            .register_protocol("Frame", "Frame", "frame")
            .unwrap_or(ProtocolId(0));
        // Register core `frame.*` fields
        let _ = registry.register_field(
            frame_proto_id,
            "frame.number",
            "Frame Number",
            FieldType::Uint64,
            "1-based frame ordinal in capture",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.len",
            "Frame Length on Wire",
            FieldType::Uint32,
            "Original packet length on the wire",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.cap_len",
            "Frame Captured Length",
            FieldType::Uint32,
            "Captured byte length in file",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.time_epoch",
            "Epoch Time",
            FieldType::Float64,
            "Seconds since Unix epoch",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.time_relative",
            "Time Relative to First Packet",
            FieldType::RelativeTime,
            "Seconds since first packet in capture",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.time_delta",
            "Time Delta from Previous Packet",
            FieldType::RelativeTime,
            "Seconds since previous packet",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.interface_id",
            "Interface ID",
            FieldType::Uint32,
            "Capture interface identifier",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.protocols",
            "Protocols in Frame",
            FieldType::String,
            "Colon-separated list of protocols in frame",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.comment",
            "Frame Comment",
            FieldType::String,
            "User packet annotation",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.marked",
            "Frame is Marked",
            FieldType::Bool,
            "True if packet is marked",
        );
        let _ = registry.register_field(
            frame_proto_id,
            "frame.ignored",
            "Frame is Ignored",
            FieldType::Bool,
            "True if packet is ignored",
        );

        let data_proto_id = registry
            .register_protocol("Data", "Data", "data")
            .unwrap_or(ProtocolId(1));
        let _ = registry.register_field(
            data_proto_id,
            "data.data",
            "Data",
            FieldType::Bytes,
            "Raw undissected payload bytes",
        );
        let _ = registry.register_field(
            data_proto_id,
            "data.len",
            "Length",
            FieldType::Uint32,
            "Payload byte length",
        );

        Self {
            registry,
            dissectors: HashMap::new(),
            tables: HashMap::new(),
            tcp_heuristics: Vec::new(),
            udp_heuristics: Vec::new(),
            decode_as: DecodeAsTable::new(),
            frame_proto_id,
            data_proto_id,
        }
    }

    pub fn register_dissector(&mut self, dissector: Arc<dyn Dissector>) {
        self.dissectors.insert(dissector.protocol(), dissector);
    }

    pub fn register_table_entry(&mut self, table: TableId, key: u32, proto_id: ProtocolId) {
        self.tables.insert((table, key), proto_id);
    }

    pub fn register_tcp_heuristic(&mut self, proto_id: ProtocolId) {
        if !self.tcp_heuristics.contains(&proto_id) {
            self.tcp_heuristics.push(proto_id);
        }
    }

    pub fn register_udp_heuristic(&mut self, proto_id: ProtocolId) {
        if !self.udp_heuristics.contains(&proto_id) {
            self.udp_heuristics.push(proto_id);
        }
    }

    pub fn lookup_table(&self, table: TableId, key: u32) -> Option<ProtocolId> {
        if let Some(override_name) = self.decode_as.get(table, key) {
            if let Some(meta) = self.registry.protocol_by_filter(override_name) {
                return Some(meta.id);
            }
        }
        self.tables.get(&(table, key)).copied()
    }

    pub fn resolve_port_dissector(
        &self,
        table: TableId,
        src_port: u16,
        dst_port: u16,
        remaining_slice: &[u8],
        ctx: &DissectCtx<'_>,
    ) -> Option<ProtocolId> {
        // 1. User Decode-As overrides take highest priority
        if let Some(name) = self
            .decode_as
            .get(table, dst_port as u32)
            .or_else(|| self.decode_as.get(table, src_port as u32))
        {
            if let Some(meta) = self.registry.protocol_by_filter(name) {
                return Some(meta.id);
            }
        }

        // 2. Registered well-known ports (prefer lower well-known port if one side is ephemeral)
        let dst_reg = self.tables.get(&(table, dst_port as u32)).copied();
        let src_reg = self.tables.get(&(table, src_port as u32)).copied();
        match (dst_reg, src_reg) {
            (Some(d), Some(s)) => {
                if dst_port <= src_port {
                    return Some(d);
                } else {
                    return Some(s);
                }
            }
            (Some(d), None) => return Some(d),
            (None, Some(s)) => return Some(s),
            (None, None) => {}
        }

        // 3. Heuristic dissectors
        if !remaining_slice.is_empty() {
            let list = match table {
                TableId::TcpPort => &self.tcp_heuristics,
                TableId::UdpPort => &self.udp_heuristics,
                _ => return None,
            };
            for &proto_id in list {
                if let Some(d) = self.dissectors.get(&proto_id) {
                    if d.heuristic_probe(remaining_slice, ctx) {
                        return Some(proto_id);
                    }
                }
            }
        }

        None
    }

    /// Dissect a single `Frame`, catching any unexpected panic (`REL-01`) and enforcing recursion bounds (`REL-03`).
    pub fn dissect_frame(
        &self,
        frame: &Frame,
        first_ts: Option<Timestamp>,
        prev_ts: Option<Timestamp>,
        resolver: &mut NameResolver,
        conversations: &mut ConversationTracker,
    ) -> DissectedPacket {
        let rel_time_sec = first_ts
            .map(|t0| frame.timestamp.delta_secs_f64(t0))
            .unwrap_or(0.0);
        let delta_time_sec = prev_ts
            .map(|tp| frame.timestamp.delta_secs_f64(tp))
            .unwrap_or(0.0);

        let summary = PacketSummary {
            number: frame.number,
            timestamp: frame.timestamp,
            rel_time_sec,
            delta_time_sec,
            source: String::new(),
            destination: String::new(),
            protocol: frame.link_type.name().to_string(),
            length: frame.orig_len,
            info: format!("{} ({} bytes)", frame.link_type.name(), frame.captured_len),
            max_expert: None,
        };

        let mut ctx = DissectCtx {
            frame,
            registry: &self.registry,
            resolver,
            conversations,
            summary,
            tree: FieldTree::new(),
            depth: 0,
            current_proto: self.frame_proto_id,
            net_src_raw: None,
            net_dst_raw: None,
            src_port: None,
            dst_port: None,
            stream_id: None,
        };

        let full_range = ByteRange::new(0, frame.data.len());
        let frame_label = format!(
            "Frame {}: {} bytes on wire ({} bits), {} bytes captured ({} bits) on interface {}",
            frame.number,
            frame.orig_len,
            frame.orig_len.saturating_mul(8),
            frame.captured_len,
            frame.captured_len.saturating_mul(8),
            frame.interface_id
        );
        let frame_root = ctx.begin_protocol(self.frame_proto_id, frame_label, full_range);
        ctx.add_u64(
            Some(frame_root),
            "frame.number",
            frame.number,
            full_range,
            None,
        );
        ctx.add_u64(
            Some(frame_root),
            "frame.len",
            frame.orig_len as u64,
            full_range,
            None,
        );
        ctx.add_u64(
            Some(frame_root),
            "frame.cap_len",
            frame.captured_len as u64,
            full_range,
            None,
        );
        ctx.add_field(
            Some(frame_root),
            "frame.time_epoch",
            FieldValue::F64(frame.timestamp.as_secs_f64()),
            full_range,
            Some(format!(
                "Epoch Time: {} seconds",
                frame.timestamp.format_epoch()
            )),
            false,
        );
        ctx.add_generated_f64(
            Some(frame_root),
            "frame.time_relative",
            rel_time_sec,
            full_range,
            Some(format!(
                "[Time since reference or first frame: {rel_time_sec:.9} seconds]"
            )),
        );
        ctx.add_generated_f64(
            Some(frame_root),
            "frame.time_delta",
            delta_time_sec,
            full_range,
            Some(format!(
                "[Time delta from previous captured frame: {delta_time_sec:.9} seconds]"
            )),
        );
        ctx.add_u64(
            Some(frame_root),
            "frame.interface_id",
            frame.interface_id as u64,
            full_range,
            None,
        );
        for c in &frame.comments {
            let c_node = ctx.add_str(
                Some(frame_root),
                "frame.comment",
                c.clone(),
                full_range,
                None,
            );
            ctx.add_expert(
                c_node,
                ExpertSeverity::Chat,
                ExpertGroup::Comments,
                c.clone(),
                full_range,
            );
        }
        if frame.flags.marked {
            ctx.add_bool(Some(frame_root), "frame.marked", true, full_range, None);
        }
        if frame.flags.ignored {
            ctx.add_bool(Some(frame_root), "frame.ignored", true, full_range, None);
        }

        let mut cursor = PacketCursor::new(&frame.data);
        let initial_next = Next::Table(TableId::LinkType, frame.link_type.to_u32());
        self.run_chain(&mut ctx, &mut cursor, initial_next);

        // Also dissect any attached secondary data sources (e.g., Decrypted TLS or Reassembled HTTP)
        for (idx, source) in frame.extra_sources.iter().enumerate() {
            let source_idx = (idx + 1) as u8;
            let name_lower = source.name.to_ascii_lowercase();
            let target_proto = if name_lower.contains("http") {
                self.registry.protocol_by_filter("http").map(|p| p.id)
            } else if name_lower.contains("dns") {
                self.registry.protocol_by_filter("dns").map(|p| p.id)
            } else if name_lower.contains("tls") || name_lower.contains("decrypted") {
                // Probe decrypted payload with HTTP or DNS heuristic if available
                self.registry.protocol_by_filter("http").map(|p| p.id)
            } else {
                None
            };
            if let Some(pid) = target_proto {
                let mut sub_cursor = PacketCursor::with_source(&source.data, source_idx, 0);
                self.run_chain(&mut ctx, &mut sub_cursor, Next::Dissector(pid));
            }
        }

        // Populate `frame.protocols` generated string
        let protos_joined = ctx.tree.protocols_in_frame.join(":");
        ctx.add_generated_str(
            Some(frame_root),
            "frame.protocols",
            protos_joined.clone(),
            full_range,
            Some(format!("[Protocols in frame: {protos_joined}]")),
        );

        DissectedPacket {
            summary: ctx.summary,
            tree: ctx.tree,
        }
    }

    fn run_chain(
        &self,
        ctx: &mut DissectCtx<'_>,
        cursor: &mut PacketCursor<'_>,
        mut next: Next,
    ) {
        while !matches!(next, Next::None) {
            if ctx.depth >= MAX_RECURSION_DEPTH {
                let node = ctx.begin_protocol(
                    self.data_proto_id,
                    "Recursion Depth Limit Reached",
                    cursor.remaining_range(),
                );
                ctx.add_expert(
                    node,
                    ExpertSeverity::Error,
                    ExpertGroup::Protocol,
                    format!("Exceeded maximum encapsulation recursion depth ({MAX_RECURSION_DEPTH})"),
                    cursor.remaining_range(),
                );
                break;
            }

            let target_proto = match next {
                Next::None => break,
                Next::Table(table, key) => self.lookup_table(table, key),
                Next::Ports {
                    table,
                    src_port,
                    dst_port,
                } => self.resolve_port_dissector(
                    table,
                    src_port,
                    dst_port,
                    cursor.slice_remaining(),
                    ctx,
                ),
                Next::Dissector(pid) => Some(pid),
                Next::NeedMore { needed } => {
                    let rem = cursor.remaining_range();
                    let last_root = ctx.tree.roots.last().copied().unwrap_or(NodeId(0));
                    ctx.add_expert(
                        last_root,
                        ExpertSeverity::Chat,
                        ExpertGroup::Reassemble,
                        match needed {
                            Some(n) => format!("PDU incomplete, requires {n} additional bytes"),
                            None => "PDU continues in subsequent segment".to_string(),
                        },
                        rem,
                    );
                    break;
                }
            };

            let Some(proto_id) = target_proto else {
                // Undissected trailing payload -> attach `data` node if bytes remain
                if !cursor.is_empty() {
                    let rem_range = cursor.remaining_range();
                    let rem_bytes = cursor.slice_remaining().to_vec();
                    let len = rem_bytes.len();
                    let data_root = ctx.tree.add_node(
                        None,
                        FieldId(0),
                        self.data_proto_id,
                        "data",
                        "Data",
                        format!("Data ({len} bytes)"),
                        FieldType::None,
                        FieldValue::None,
                        rem_range,
                        false,
                    );
                    ctx.tree.add_protocol_in_frame("data");
                    ctx.add_bytes(Some(data_root), "data.data", rem_bytes, rem_range, None);
                    ctx.add_u64(
                        Some(data_root),
                        "data.len",
                        len as u64,
                        rem_range,
                        Some(format!("[Length: {len}]")),
                    );
                }
                break;
            };

            let Some(dissector) = self.dissectors.get(&proto_id) else {
                break;
            };

            ctx.depth += 1;
            ctx.current_proto = proto_id;
            let start_range = cursor.remaining_range();

            // Run dissector inside catch_unwind to guarantee REL-01 (never panic on hostile input)
            let outcome = catch_unwind(AssertUnwindSafe(|| dissector.dissect(ctx, cursor)));

            match outcome {
                Ok(Ok(next_step)) => {
                    next = next_step;
                }
                Ok(Err(trunc)) => {
                    let proto_name = self
                        .registry
                        .protocol(proto_id)
                        .map(|p| p.short_name.clone())
                        .unwrap_or_else(|| "Packet".to_string());
                    let err_range = ByteRange::with_source(
                        cursor.source_idx(),
                        trunc.offset,
                        trunc.offset + trunc.available,
                    );
                    let target_node = ctx.tree.roots.last().copied().unwrap_or(NodeId(0));
                    ctx.add_expert(
                        target_node,
                        ExpertSeverity::Error,
                        ExpertGroup::Malformed,
                        format!(
                            "Malformed Packet ({proto_name}: needed {} bytes at offset {}, only {} available)",
                            trunc.needed, trunc.offset, trunc.available
                        ),
                        err_range,
                    );
                    ctx.append_info(&format!(" [Malformed Packet: {proto_name}]"));
                    break;
                }
                Err(_) => {
                    let proto_name = self
                        .registry
                        .protocol(proto_id)
                        .map(|p| p.short_name.clone())
                        .unwrap_or_else(|| "Dissector".to_string());
                    let target_node = ctx.tree.roots.last().copied().unwrap_or(NodeId(0));
                    ctx.add_expert(
                        target_node,
                        ExpertSeverity::Error,
                        ExpertGroup::Malformed,
                        format!("Internal dissector fault recovered in {proto_name}"),
                        start_range,
                    );
                    ctx.append_info(&format!(" [Dissector Error: {proto_name}]"));
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_rejects_conflicting_duplicate_fields_and_suggests_closest() {
        let mut reg = Registry::new();
        let pid = reg
            .register_protocol("Internet Protocol v4", "IPv4", "ip")
            .unwrap();
        reg.register_field(pid, "ip.src", "Source Address", FieldType::Ipv4, "")
            .unwrap();
        reg.register_field(pid, "ip.dst", "Destination Address", FieldType::Ipv4, "")
            .unwrap();

        // Conflicting type for `ip.src` must error
        let conflict = reg.register_field(pid, "ip.src", "Source", FieldType::Uint32, "");
        assert!(conflict.is_err());

        let suggestions = reg.did_you_mean("ip.scr", 3);
        assert!(suggestions.contains(&"ip.src".to_string()));
    }

    #[test]
    fn packet_cursor_bounds_checks_and_records_byte_ranges() {
        let raw = [0x12, 0x34, 0x56, 0x78];
        let mut cur = PacketCursor::new(&raw);
        let (v1, r1) = cur.read_u16_be().unwrap();
        assert_eq!(v1, 0x1234);
        assert_eq!(r1, ByteRange::new(0, 2));

        // Reading 4 bytes when only 2 remain must return TruncatedError, never panic
        let err = cur.read_u32_be().unwrap_err();
        assert_eq!(err.offset, 2);
        assert_eq!(err.needed, 4);
        assert_eq!(err.available, 2);
    }

    #[test]
    fn decode_as_parses_cli_selector() {
        let mut da = DecodeAsTable::new();
        da.parse_and_insert("tcp.port==8443,http").unwrap();
        assert_eq!(da.get(TableId::TcpPort, 8443), Some("http"));
    }
}

