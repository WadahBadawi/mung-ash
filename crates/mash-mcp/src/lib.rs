use mash_core::{DissectedPacket, ExpertSeverity, Frame, NameResolver, ResolutionConfig, Result};
use mash_dissect::{ConversationTracker, DissectorEngine};
use mash_filter::CompiledFilter;
use mash_pcapfile::{read_capture_file, CaptureFile};
use mash_protocols::build_default_engine;
use mash_reassembly::{ReassembledStream, StreamDisplayFormat};
use mash_stats::{
    analyze_tcp_flows, build_protocol_hierarchy, compute_conversations, summarize_expert_info,
    ConversationLayer,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

/// JSON-RPC 2.0 request envelope for MCP (`AI-21`).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// JSON-RPC 2.0 response envelope for MCP (`AI-21`).
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Active capture analysis session backing `mash-mcp` and agentic tool calls (`AI-20`, `AI-21`).
pub struct McpServer {
    pub engine: DissectorEngine,
    pub frames: Vec<Frame>,
    pub dissected: Vec<DissectedPacket>,
    pub tcp_streams: BTreeMap<u32, ReassembledStream>,
    pub udp_streams: BTreeMap<u32, ReassembledStream>,
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            engine: build_default_engine(),
            frames: Vec::new(),
            dissected: Vec::new(),
            tcp_streams: BTreeMap::new(),
            udp_streams: BTreeMap::new(),
        }
    }

    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let cap = read_capture_file(path)?;
        self.load_capture(cap);
        Ok(())
    }

    pub fn load_capture(&mut self, cap: CaptureFile) {
        let mut resolver = NameResolver::new(ResolutionConfig::default());
        cap.populate_name_resolver(&mut resolver);
        let mut conv = ConversationTracker::new();

        self.frames = cap.frames;
        self.dissected.clear();
        self.tcp_streams.clear();
        self.udp_streams.clear();

        let first_ts = self.frames.first().map(|f| f.timestamp);
        let mut prev_ts = None;

        for frame in &self.frames {
            let pkt = self
                .engine
                .dissect_frame(frame, first_ts, prev_ts, &mut resolver, &mut conv);
            prev_ts = Some(frame.timestamp);

            // Populate TCP/UDP stream buffers for `follow_stream`
            if let Some(sid) = pkt
                .tree
                .by_abbrev("tcp.stream")
                .next()
                .and_then(|n| n.value.as_u64())
                .map(|v| v as u32)
            {
                let sport = pkt
                    .tree
                    .by_abbrev("tcp.srcport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let dport = pkt
                    .tree
                    .by_abbrev("tcp.dstport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let seq = pkt
                    .tree
                    .by_abbrev("tcp.seq")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u32;
                let flags = pkt
                    .tree
                    .by_abbrev("tcp.flags")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let tcp_node = pkt.tree.by_abbrev("tcp").next();
                let payload_start = tcp_node.map(|n| n.byte_range.end).unwrap_or(frame.data.len());
                let payload = frame.data.get(payload_start..).unwrap_or(&[]);
                let stream = self
                    .tcp_streams
                    .entry(sid)
                    .or_insert_with(|| ReassembledStream::new(sid));
                stream.push_tcp_segment(
                    frame.number,
                    frame.timestamp,
                    &pkt.summary.source,
                    sport,
                    &pkt.summary.destination,
                    dport,
                    seq,
                    (flags & 0x02) != 0,
                    payload,
                );
            } else if let Some(sid) = pkt
                .tree
                .by_abbrev("udp.stream")
                .next()
                .and_then(|n| n.value.as_u64())
                .map(|v| v as u32)
            {
                let sport = pkt
                    .tree
                    .by_abbrev("udp.srcport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let dport = pkt
                    .tree
                    .by_abbrev("udp.dstport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let udp_node = pkt.tree.by_abbrev("udp").next();
                let payload_start = udp_node.map(|n| n.byte_range.end).unwrap_or(frame.data.len());
                let payload = frame.data.get(payload_start..).unwrap_or(&[]);
                let stream = self
                    .udp_streams
                    .entry(sid)
                    .or_insert_with(|| ReassembledStream::new(sid));
                stream.push_udp_datagram(
                    frame.number,
                    frame.timestamp,
                    &pkt.summary.source,
                    sport,
                    &pkt.summary.destination,
                    dport,
                    payload,
                );
            }

            self.dissected.push(pkt);
        }

        let _ = analyze_tcp_flows(&mut self.dissected);
    }

    pub fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.unwrap_or(Value::Null);
        match req.method.as_str() {
            "initialize" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "mash-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
                error: None,
            },
            "ping" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({})),
                error: None,
            },
            "tools/list" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "tools": [
                        {
                            "name": "query_packets",
                            "description": "Filter packets with a MUNG-ASH display filter and return summaries and optional extracted fields.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "filter": { "type": "string" },
                                    "limit": { "type": "integer" },
                                    "offset": { "type": "integer" },
                                    "fields": { "type": "array", "items": { "type": "string" } }
                                }
                            }
                        },
                        {
                            "name": "get_packet_detail",
                            "description": "Return the full dissected protocol field tree for a 1-based frame number.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "frame_number": { "type": "integer" }
                                },
                                "required": ["frame_number"]
                            }
                        },
                        {
                            "name": "follow_stream",
                            "description": "Reconstruct a TCP or UDP conversation stream by stream index.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "protocol": { "type": "string", "enum": ["tcp", "udp"] },
                                    "stream_id": { "type": "integer" }
                                },
                                "required": ["protocol", "stream_id"]
                            }
                        },
                        {
                            "name": "get_conversations",
                            "description": "Return bidirectional conversation statistics for eth, ip, ipv6, tcp, or udp.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "layer": { "type": "string", "enum": ["eth", "ip", "ipv6", "tcp", "udp"] }
                                }
                            }
                        },
                        {
                            "name": "get_protocol_hierarchy",
                            "description": "Return protocol hierarchy statistics for the loaded capture.",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "get_expert_info",
                            "description": "Return aggregated Expert Info anomalies and protocol warnings.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "min_severity": { "type": "string", "enum": ["chat", "note", "warn", "error"] }
                                }
                            }
                        }
                    ]
                })),
                error: None,
            },
            "tools/call" => {
                let tool_name = req
                    .params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
                match self.call_tool(tool_name, &args) {
                    Ok(val) => JsonRpcResponse {
                        jsonrpc: "2.0",
                        id,
                        result: Some(json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&val).unwrap_or_default()
                            }],
                            "structuredContent": val
                        })),
                        error: None,
                    },
                    Err(msg) => JsonRpcResponse {
                        jsonrpc: "2.0",
                        id,
                        result: None,
                        error: Some(json!({ "code": -32602, "message": msg })),
                    },
                }
            }
            other => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(json!({
                    "code": -32601,
                    "message": format!("Unknown MCP method '{other}'")
                })),
            },
        }
    }

    pub fn call_tool(
        &self,
        tool_name: &str,
        args: &Value,
    ) -> std::result::Result<Value, String> {
        match tool_name {
            "query_packets" => {
                let filter_str = args.get("filter").and_then(|v| v.as_str()).unwrap_or("");
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100)
                    .min(1000) as usize;
                let offset = args
                    .get("offset")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                let fields: Vec<String> = args
                    .get("fields")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let compiled =
                    CompiledFilter::compile(filter_str, Some(&self.engine.registry))
                        .map_err(|e| e.to_string())?;

                let mut matched = Vec::new();
                for pkt in self
                    .dissected
                    .iter()
                    .filter(|p| compiled.matches(p))
                    .skip(offset)
                    .take(limit)
                {
                    let mut extracted = serde_json::Map::new();
                    for f in &fields {
                        let vals: Vec<String> = pkt
                            .tree
                            .by_abbrev(f)
                            .map(|n| n.value.display_value())
                            .collect();
                        extracted.insert(f.clone(), json!(vals));
                    }
                    matched.push(json!({
                        "summary": pkt.summary,
                        "fields": extracted
                    }));
                }
                Ok(json!({ "count": matched.len(), "packets": matched }))
            }
            "get_packet_detail" => {
                let frame_no = args
                    .get("frame_number")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| "Missing 'frame_number'".to_string())?;
                if frame_no == 0 || (frame_no as usize) > self.dissected.len() {
                    return Err(format!("Frame {frame_no} out of range"));
                }
                let pkt = &self.dissected[(frame_no - 1) as usize];
                Ok(serde_json::to_value(pkt).map_err(|e| e.to_string())?)
            }
            "follow_stream" => {
                let proto = args
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tcp")
                    .to_ascii_lowercase();
                let stream_id = args
                    .get("stream_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let stream = if proto == "udp" {
                    self.udp_streams.get(&stream_id)
                } else {
                    self.tcp_streams.get(&stream_id)
                };
                match stream {
                    Some(s) => Ok(json!({
                        "stream_id": stream_id,
                        "protocol": proto,
                        "client": s.client_endpoint,
                        "server": s.server_endpoint,
                        "ascii": s.format_stream(StreamDisplayFormat::Ascii)
                    })),
                    None => Err(format!("Stream {proto} #{stream_id} not found")),
                }
            }
            "get_conversations" => {
                let layer_str = args
                    .get("layer")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ip")
                    .to_ascii_lowercase();
                let layer = match layer_str.as_str() {
                    "eth" => ConversationLayer::Ethernet,
                    "ipv6" => ConversationLayer::Ipv6,
                    "tcp" => ConversationLayer::Tcp,
                    "udp" => ConversationLayer::Udp,
                    _ => ConversationLayer::Ipv4,
                };
                let rows = compute_conversations(&self.dissected, layer);
                Ok(serde_json::to_value(rows).map_err(|e| e.to_string())?)
            }
            "get_protocol_hierarchy" => {
                let phs = build_protocol_hierarchy(&self.dissected);
                Ok(serde_json::to_value(phs).map_err(|e| e.to_string())?)
            }
            "get_expert_info" => {
                let min_str = args
                    .get("min_severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("chat")
                    .to_ascii_lowercase();
                let min_sev = match min_str.as_str() {
                    "error" => ExpertSeverity::Error,
                    "warn" | "warning" => ExpertSeverity::Warn,
                    "note" => ExpertSeverity::Note,
                    _ => ExpertSeverity::Chat,
                };
                let rows: Vec<_> = summarize_expert_info(&self.dissected)
                    .into_iter()
                    .filter(|r| r.severity >= min_sev)
                    .collect();
                Ok(serde_json::to_value(rows).map_err(|e| e.to_string())?)
            }
            other => Err(format!("Unknown tool '{other}'")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mash_core::{LinkType, Timestamp};
    use mash_pcapfile::CaptureFormat;

    #[test]
    fn mcp_server_lists_and_calls_analysis_tools() {
        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.extend_from_slice(&[0x45, 0x00, 0x00, 40, 0, 1, 0, 0, 64, 6, 0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0x5002u16.to_be_bytes()); // SYN
        pkt.extend_from_slice(&1024u16.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);

        cap.frames
            .push(Frame::new(1, Timestamp::ZERO, LinkType::Ethernet, pkt));

        let mut server = McpServer::new();
        server.load_capture(cap);

        let res = server
            .call_tool("query_packets", &json!({ "filter": "tcp.port == 80" }))
            .unwrap();
        assert_eq!(res["count"], 1);
    }
}

