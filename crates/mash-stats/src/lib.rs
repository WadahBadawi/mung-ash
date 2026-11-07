use mash_core::{
    DissectedPacket, ExpertGroup, ExpertSeverity, Frame, Timestamp,
};
use mash_pcapfile::CaptureFile;
use mash_reassembly::decompress_http_body;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

/// Summary properties of a capture file (`mash-info` / `CLI-04`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureProperties {
    pub file_format: String,
    pub compression: String,
    pub sha256_hex: Option<String>,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub start_time: Option<Timestamp>,
    pub end_time: Option<Timestamp>,
    pub duration_secs: f64,
    pub avg_packet_size: f64,
    pub avg_packets_per_sec: f64,
    pub avg_bytes_per_sec: f64,
    pub avg_bits_per_sec: f64,
    pub interfaces: Vec<String>,
    pub comments: Vec<String>,
}

impl CaptureProperties {
    pub fn from_capture(cap: &CaptureFile, raw_file_bytes: Option<&[u8]>) -> Self {
        let sha256_hex = raw_file_bytes.map(|bytes| {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let digest = hasher.finalize();
            digest.iter().map(|b| format!("{b:02x}")).collect()
        });

        let packet_count = cap.frames.len() as u64;
        let total_bytes: u64 = cap.frames.iter().map(|f| f.orig_len as u64).sum();
        let start_time = cap.frames.iter().map(|f| f.timestamp).min();
        let end_time = cap.frames.iter().map(|f| f.timestamp).max();
        let duration_secs = match (start_time, end_time) {
            (Some(s), Some(e)) => e.delta_secs_f64(s).max(0.0),
            _ => 0.0,
        };
        let avg_packet_size = if packet_count > 0 {
            (total_bytes as f64) / (packet_count as f64)
        } else {
            0.0
        };
        let (avg_packets_per_sec, avg_bytes_per_sec, avg_bits_per_sec) = if duration_secs > 0.0 {
            let pps = (packet_count as f64) / duration_secs;
            let bps = (total_bytes as f64) / duration_secs;
            (pps, bps, bps * 8.0)
        } else {
            (0.0, 0.0, 0.0)
        };

        let interfaces = cap
            .interfaces
            .iter()
            .map(|i| format!("{} ({})", i.name, i.link_type.name()))
            .collect();

        Self {
            file_format: cap.format.name().to_string(),
            compression: format!("{:?}", cap.compression),
            sha256_hex,
            packet_count,
            total_bytes,
            start_time,
            end_time,
            duration_secs,
            avg_packet_size,
            avg_packets_per_sec,
            avg_bytes_per_sec,
            avg_bits_per_sec,
            interfaces,
            comments: cap.section_comments.clone(),
        }
    }

    pub fn format_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("File format:       {}\n", self.file_format));
        out.push_str(&format!("Compression:       {}\n", self.compression));
        if let Some(sha) = &self.sha256_hex {
            out.push_str(&format!("SHA256:            {sha}\n"));
        }
        out.push_str(&format!("Number of packets: {}\n", self.packet_count));
        out.push_str(&format!("File data size:    {} bytes\n", self.total_bytes));
        out.push_str(&format!(
            "Capture duration:  {:.6} seconds\n",
            self.duration_secs
        ));
        out.push_str(&format!(
            "Average packet:    {:.2} bytes\n",
            self.avg_packet_size
        ));
        out.push_str(&format!(
            "Packet rate:       {:.2} packets/s\n",
            self.avg_packets_per_sec
        ));
        out.push_str(&format!(
            "Data rate:         {:.2} bytes/s ({:.2} bits/s)\n",
            self.avg_bytes_per_sec, self.avg_bits_per_sec
        ));
        if !self.interfaces.is_empty() {
            out.push_str(&format!(
                "Interfaces:        {}\n",
                self.interfaces.join(", ")
            ));
        }
        out
    }
}

/// Protocol Hierarchy node (`io,phs` / `STA-04`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolHierarchyNode {
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
    pub pct_packets: f64,
    pub pct_bytes: f64,
    pub children: BTreeMap<String, ProtocolHierarchyNode>,
}

/// Build the Protocol Hierarchy tree across a slice of dissected packets (`STA-04`).
pub fn build_protocol_hierarchy(packets: &[DissectedPacket]) -> ProtocolHierarchyNode {
    let total_packets = packets.len() as u64;
    let total_bytes: u64 = packets.iter().map(|p| p.summary.length as u64).sum();

    let mut root = ProtocolHierarchyNode {
        protocol: "root".to_string(),
        packets: total_packets,
        bytes: total_bytes,
        pct_packets: 100.0,
        pct_bytes: 100.0,
        children: BTreeMap::new(),
    };

    for pkt in packets {
        let len = pkt.summary.length as u64;
        let mut curr = &mut root;
        for proto in &pkt.tree.protocols_in_frame {
            curr = curr.children.entry(proto.clone()).or_insert_with(|| {
                ProtocolHierarchyNode {
                    protocol: proto.clone(),
                    ..ProtocolHierarchyNode::default()
                }
            });
            curr.packets += 1;
            curr.bytes += len;
        }
    }

    compute_phs_percentages(&mut root, total_packets, total_bytes);
    root
}

fn compute_phs_percentages(
    node: &mut ProtocolHierarchyNode,
    total_packets: u64,
    total_bytes: u64,
) {
    if total_packets > 0 {
        node.pct_packets = (node.packets as f64) * 100.0 / (total_packets as f64);
    }
    if total_bytes > 0 {
        node.pct_bytes = (node.bytes as f64) * 100.0 / (total_bytes as f64);
    }
    for child in node.children.values_mut() {
        compute_phs_percentages(child, total_packets, total_bytes);
    }
}

impl ProtocolHierarchyNode {
    pub fn format_table(&self) -> String {
        let mut out = String::from(
            "=== Protocol Hierarchy Statistics ===\nProtocol                   Packets    % Pkts       Bytes    % Bytes\n",
        );
        for child in self.children.values() {
            format_phs_recursive(child, 0, &mut out);
        }
        out
    }
}

fn format_phs_recursive(node: &ProtocolHierarchyNode, depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    let label = format!("{indent}{}", node.protocol);
    out.push_str(&format!(
        "{label:<26} {:>7} {:>8.2}% {:>11} {:>8.2}%\n",
        node.packets, node.pct_packets, node.bytes, node.pct_bytes
    ));
    for child in node.children.values() {
        format_phs_recursive(child, depth + 1, out);
    }
}

/// Conversation layer selector (`conv,*` / `STA-03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationLayer {
    Ethernet,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
}

/// A bidirectional conversation row (`A <-> B` / `STA-03`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationRow {
    pub addr_a: String,
    pub addr_b: String,
    pub packets_a_to_b: u64,
    pub bytes_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_b_to_a: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub first_rel_sec: f64,
    pub last_rel_sec: f64,
}

impl ConversationRow {
    pub fn duration_sec(&self) -> f64 {
        (self.last_rel_sec - self.first_rel_sec).max(0.0)
    }
}

/// Compute bidirectional conversations for `layer` (`STA-03`).
pub fn compute_conversations(
    packets: &[DissectedPacket],
    layer: ConversationLayer,
) -> Vec<ConversationRow> {
    let mut map: HashMap<(String, String), ConversationRow> = HashMap::new();

    for pkt in packets {
        let Some((src, dst)) = extract_layer_endpoints(pkt, layer) else {
            continue;
        };
        let (canon_a, canon_b, is_a_to_b) = if src <= dst {
            (src, dst, true)
        } else {
            (dst, src, false)
        };
        let len = pkt.summary.length as u64;
        let rel = pkt.summary.rel_time_sec;

        let entry = map
            .entry((canon_a.clone(), canon_b.clone()))
            .or_insert_with(|| ConversationRow {
                addr_a: canon_a,
                addr_b: canon_b,
                packets_a_to_b: 0,
                bytes_a_to_b: 0,
                packets_b_to_a: 0,
                bytes_b_to_a: 0,
                total_packets: 0,
                total_bytes: 0,
                first_rel_sec: rel,
                last_rel_sec: rel,
            });

        if is_a_to_b {
            entry.packets_a_to_b += 1;
            entry.bytes_a_to_b += len;
        } else {
            entry.packets_b_to_a += 1;
            entry.bytes_b_to_a += len;
        }
        entry.total_packets += 1;
        entry.total_bytes += len;
        entry.first_rel_sec = entry.first_rel_sec.min(rel);
        entry.last_rel_sec = entry.last_rel_sec.max(rel);
    }

    let mut rows: Vec<ConversationRow> = map.into_values().collect();
    rows.sort_by_key(|a| std::cmp::Reverse(a.total_bytes));
    rows
}

/// Endpoint summary row (`STA-03`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRow {
    pub address: String,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
}

/// Compute endpoint traffic statistics for `layer` (`STA-03`).
pub fn compute_endpoints(
    packets: &[DissectedPacket],
    layer: ConversationLayer,
) -> Vec<EndpointRow> {
    let mut map: HashMap<String, EndpointRow> = HashMap::new();
    for pkt in packets {
        let Some((src, dst)) = extract_layer_endpoints(pkt, layer) else {
            continue;
        };
        let len = pkt.summary.length as u64;

        let tx = map.entry(src.clone()).or_insert_with(|| EndpointRow {
            address: src,
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            total_packets: 0,
            total_bytes: 0,
        });
        tx.tx_packets += 1;
        tx.tx_bytes += len;
        tx.total_packets += 1;
        tx.total_bytes += len;

        let rx = map.entry(dst.clone()).or_insert_with(|| EndpointRow {
            address: dst,
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            total_packets: 0,
            total_bytes: 0,
        });
        rx.rx_packets += 1;
        rx.rx_bytes += len;
        rx.total_packets += 1;
        rx.total_bytes += len;
    }

    let mut rows: Vec<EndpointRow> = map.into_values().collect();
    rows.sort_by_key(|a| std::cmp::Reverse(a.total_bytes));
    rows
}

fn extract_layer_endpoints(
    pkt: &DissectedPacket,
    layer: ConversationLayer,
) -> Option<(String, String)> {
    match layer {
        ConversationLayer::Ethernet => {
            let s = pkt.tree.by_abbrev("eth.src").next()?.value.display_value();
            let d = pkt.tree.by_abbrev("eth.dst").next()?.value.display_value();
            Some((s, d))
        }
        ConversationLayer::Ipv4 => {
            let s = pkt.tree.by_abbrev("ip.src").next()?.value.display_value();
            let d = pkt.tree.by_abbrev("ip.dst").next()?.value.display_value();
            Some((s, d))
        }
        ConversationLayer::Ipv6 => {
            let s = pkt.tree.by_abbrev("ipv6.src").next()?.value.display_value();
            let d = pkt.tree.by_abbrev("ipv6.dst").next()?.value.display_value();
            Some((s, d))
        }
        ConversationLayer::Tcp => {
            let ip_s = pkt
                .tree
                .by_abbrev("ip.src")
                .next()
                .or_else(|| pkt.tree.by_abbrev("ipv6.src").next())?
                .value
                .display_value();
            let ip_d = pkt
                .tree
                .by_abbrev("ip.dst")
                .next()
                .or_else(|| pkt.tree.by_abbrev("ipv6.dst").next())?
                .value
                .display_value();
            let p_s = pkt.tree.by_abbrev("tcp.srcport").next()?.value.as_u64()?;
            let p_d = pkt.tree.by_abbrev("tcp.dstport").next()?.value.as_u64()?;
            Some((format!("{ip_s}:{p_s}"), format!("{ip_d}:{p_d}")))
        }
        ConversationLayer::Udp => {
            let ip_s = pkt
                .tree
                .by_abbrev("ip.src")
                .next()
                .or_else(|| pkt.tree.by_abbrev("ipv6.src").next())?
                .value
                .display_value();
            let ip_d = pkt
                .tree
                .by_abbrev("ip.dst")
                .next()
                .or_else(|| pkt.tree.by_abbrev("ipv6.dst").next())?
                .value
                .display_value();
            let p_s = pkt.tree.by_abbrev("udp.srcport").next()?.value.as_u64()?;
            let p_d = pkt.tree.by_abbrev("udp.dstport").next()?.value.as_u64()?;
            Some((format!("{ip_s}:{p_s}"), format!("{ip_d}:{p_d}")))
        }
    }
}

/// Packet length distribution bucket (`plen` / `STA-04`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LengthBucket {
    pub label: &'static str,
    pub min_len: u32,
    pub max_len: Option<u32>,
    pub count: u64,
    pub percentage: f64,
}

/// Compute packet length distribution (`STA-04`).
pub fn compute_packet_length_distribution(packets: &[DissectedPacket]) -> Vec<LengthBucket> {
    const BUCKETS: &[(&str, u32, Option<u32>)] = &[
        ("0-19", 0, Some(19)),
        ("20-39", 20, Some(39)),
        ("40-79", 40, Some(79)),
        ("80-159", 80, Some(159)),
        ("160-319", 160, Some(319)),
        ("320-639", 320, Some(639)),
        ("640-1279", 640, Some(1279)),
        ("1280-2559", 1280, Some(2559)),
        ("2560-5119", 2560, Some(5119)),
        ("5120+", 5120, None),
    ];

    let total = packets.len() as f64;
    let mut out: Vec<LengthBucket> = BUCKETS
        .iter()
        .map(|&(label, min_len, max_len)| LengthBucket {
            label,
            min_len,
            max_len,
            count: 0,
            percentage: 0.0,
        })
        .collect();

    for pkt in packets {
        let len = pkt.summary.length;
        for b in &mut out {
            let in_bucket = match b.max_len {
                Some(max) => len >= b.min_len && len <= max,
                None => len >= b.min_len,
            };
            if in_bucket {
                b.count += 1;
                break;
            }
        }
    }

    if total > 0.0 {
        for b in &mut out {
            b.percentage = (b.count as f64) * 100.0 / total;
        }
    }
    out
}

/// Detected TCP anomaly on a single frame (`STA-02`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpAnomaly {
    Retransmission,
    FastRetransmission,
    OutOfOrder,
    DuplicateAck(u32),
    ZeroWindow,
    WindowUpdate,
    KeepAlive,
}

impl TcpAnomaly {
    pub fn label(&self) -> String {
        match self {
            Self::Retransmission => "[TCP Retransmission]".to_string(),
            Self::FastRetransmission => "[TCP Fast Retransmission]".to_string(),
            Self::OutOfOrder => "[TCP Out-Of-Order]".to_string(),
            Self::DuplicateAck(n) => format!("[TCP Dup ACK #{n}]"),
            Self::ZeroWindow => "[TCP ZeroWindow]".to_string(),
            Self::WindowUpdate => "[TCP Window Update]".to_string(),
            Self::KeepAlive => "[TCP Keep-Alive]".to_string(),
        }
    }
}

/// Stateful TCP sequence, window, and RTT analyzer (`STA-02`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpFlowHealth {
    pub stream_id: u32,
    pub retransmissions: u64,
    pub fast_retransmissions: u64,
    pub out_of_order: u64,
    pub duplicate_acks: u64,
    pub zero_windows: u64,
    pub keep_alives: u64,
    pub rtt_samples_ms: Vec<f64>,
    pub frame_anomalies: HashMap<u64, Vec<TcpAnomaly>>,
}

#[derive(Default)]
struct DirState {
    highest_next_seq: Option<u32>,
    last_ack: Option<u32>,
    last_win: Option<u16>,
    dup_ack_count: u32,
    sent_times: BTreeMap<u32, Timestamp>,
}

/// Analyze TCP flows across dissected packets, attaching `ExpertItem`s (`STA-02`, `STA-05`) and computing per-stream health metrics.
pub fn analyze_tcp_flows(packets: &mut [DissectedPacket]) -> BTreeMap<u32, TcpFlowHealth> {
    let mut flows: BTreeMap<u32, TcpFlowHealth> = BTreeMap::new();
    let mut dir_states: HashMap<(u32, String, u16), DirState> = HashMap::new();

    for pkt in packets {
        let Some(stream_id) = pkt
            .tree
            .by_abbrev("tcp.stream")
            .next()
            .and_then(|n| n.value.as_u64())
            .map(|v| v as u32)
        else {
            continue;
        };
        let Some(seq) = pkt
            .tree
            .by_abbrev("tcp.seq")
            .next()
            .and_then(|n| n.value.as_u64())
            .map(|v| v as u32)
        else {
            continue;
        };
        let ack = pkt
            .tree
            .by_abbrev("tcp.ack")
            .next()
            .and_then(|n| n.value.as_u64())
            .unwrap_or(0) as u32;
        let seg_len = pkt
            .tree
            .by_abbrev("tcp.len")
            .next()
            .and_then(|n| n.value.as_u64())
            .unwrap_or(0) as u32;
        let win = pkt
            .tree
            .by_abbrev("tcp.window_size_value")
            .next()
            .and_then(|n| n.value.as_u64())
            .unwrap_or(0) as u16;
        let flags = pkt
            .tree
            .by_abbrev("tcp.flags")
            .next()
            .and_then(|n| n.value.as_u64())
            .unwrap_or(0) as u16;
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

        let f_syn = (flags & 0x02) != 0;
        let f_fin = (flags & 0x01) != 0;
        let f_rst = (flags & 0x04) != 0;
        let f_ack = (flags & 0x10) != 0;

        let src_addr = pkt.summary.source.clone();
        let dst_addr = pkt.summary.destination.clone();

        let health = flows.entry(stream_id).or_insert_with(|| TcpFlowHealth {
            stream_id,
            ..TcpFlowHealth::default()
        });

        // Check RTT against reverse direction's sent sequence numbers
        if f_ack {
            if let Some(rev) = dir_states.get_mut(&(stream_id, dst_addr.clone(), dport)) {
                if let Some(&sent_ts) = rev.sent_times.get(&ack) {
                    let rtt_ms = pkt.summary.timestamp.delta_secs_f64(sent_ts) * 1_000.0;
                    if rtt_ms >= 0.0 {
                        health.rtt_samples_ms.push(rtt_ms);
                    }
                }
            }
        }

        let reverse_dup_acks = dir_states
            .get(&(stream_id, dst_addr, dport))
            .map(|r| r.dup_ack_count)
            .unwrap_or(0);

        let state = dir_states
            .entry((stream_id, src_addr, sport))
            .or_default();

        let mut anomalies = Vec::new();
        let advance = seg_len + u32::from(f_syn) + u32::from(f_fin);

        if advance > 0 {
            let next_seq = seq.wrapping_add(advance);
            state.sent_times.insert(next_seq, pkt.summary.timestamp);
            if let Some(highest) = state.highest_next_seq {
                if (seq.wrapping_sub(highest) as i32) < 0 {
                    // Check keep-alive (1-byte at highest - 1)
                    if seg_len <= 1 && seq.wrapping_add(1) == highest && !f_syn && !f_fin {
                        anomalies.push(TcpAnomaly::KeepAlive);
                        health.keep_alives += 1;
                    } else if reverse_dup_acks >= 3 {
                        anomalies.push(TcpAnomaly::FastRetransmission);
                        health.fast_retransmissions += 1;
                    } else {
                        anomalies.push(TcpAnomaly::Retransmission);
                        health.retransmissions += 1;
                    }
                } else if (seq.wrapping_sub(highest) as i32) > 0 {
                    anomalies.push(TcpAnomaly::OutOfOrder);
                    health.out_of_order += 1;
                    state.highest_next_seq = Some(next_seq);
                } else {
                    state.highest_next_seq = Some(next_seq);
                }
            } else {
                state.highest_next_seq = Some(next_seq);
            }
        } else if f_ack && !f_syn && !f_fin && !f_rst {
            // Pure ACK -> check ZeroWindow, WindowUpdate, or Duplicate ACK
            if win == 0 {
                anomalies.push(TcpAnomaly::ZeroWindow);
                health.zero_windows += 1;
            } else if state.last_ack == Some(ack) {
                if state.last_win == Some(win) {
                    state.dup_ack_count += 1;
                    anomalies.push(TcpAnomaly::DuplicateAck(state.dup_ack_count));
                    health.duplicate_acks += 1;
                } else {
                    anomalies.push(TcpAnomaly::WindowUpdate);
                }
            } else {
                state.dup_ack_count = 0;
            }
        }

        state.last_ack = Some(ack);
        state.last_win = Some(win);

        if !anomalies.is_empty() {
            for anom in &anomalies {
                let lbl = anom.label();
                pkt.summary.info = format!("{lbl} {}", pkt.summary.info);
                if let Some(&tcp_root) = pkt.tree.roots.last() {
                    let sev = match anom {
                        TcpAnomaly::ZeroWindow => ExpertSeverity::Warn,
                        TcpAnomaly::Retransmission
                        | TcpAnomaly::FastRetransmission
                        | TcpAnomaly::OutOfOrder
                        | TcpAnomaly::DuplicateAck(_) => ExpertSeverity::Note,
                        TcpAnomaly::WindowUpdate | TcpAnomaly::KeepAlive => ExpertSeverity::Chat,
                    };
                    let item = mash_core::ExpertItem {
                        severity: sev,
                        group: ExpertGroup::Sequence,
                        protocol: "TCP".to_string(),
                        summary: lbl,
                        byte_range: mash_core::ByteRange::new(0, 0),
                    };
                    pkt.tree.attach_expert(tcp_root, item);
                    pkt.summary.max_expert = pkt.tree.max_expert_severity();
                }
            }
            health.frame_anomalies.insert(pkt.summary.number, anomalies);
        }
    }

    flows
}

/// Aggregated Expert Information summary row (`STA-05`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertSummaryRow {
    pub severity: ExpertSeverity,
    pub group: ExpertGroup,
    pub protocol: String,
    pub summary: String,
    pub count: u64,
    pub sample_frames: Vec<u64>,
}

/// Summarize all `ExpertItem`s across dissected packets (`STA-05`).
pub fn summarize_expert_info(packets: &[DissectedPacket]) -> Vec<ExpertSummaryRow> {
    let mut map: BTreeMap<(ExpertSeverity, String, String), ExpertSummaryRow> = BTreeMap::new();
    for pkt in packets {
        for exp in &pkt.tree.experts {
            let key = (exp.severity, exp.protocol.clone(), exp.summary.clone());
            let row = map.entry(key).or_insert_with(|| ExpertSummaryRow {
                severity: exp.severity,
                group: exp.group,
                protocol: exp.protocol.clone(),
                summary: exp.summary.clone(),
                count: 0,
                sample_frames: Vec::new(),
            });
            row.count += 1;
            if row.sample_frames.len() < 10 {
                row.sample_frames.push(pkt.summary.number);
            }
        }
    }
    let mut out: Vec<ExpertSummaryRow> = map.into_values().collect();
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.count.cmp(&a.count))
    });
    out
}

/// I/O Graph time-series bucket (`io,stat` / `STA-04`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoGraphBucket {
    pub start_sec: f64,
    pub end_sec: f64,
    pub packets: u64,
    pub bytes: u64,
    pub bits_per_sec: f64,
}

/// Build an I/O time-series graph with bucket width `interval_sec` (`STA-04`).
pub fn compute_io_graph(packets: &[DissectedPacket], interval_sec: f64) -> Vec<IoGraphBucket> {
    let interval = if interval_sec <= 0.0 || !interval_sec.is_finite() {
        1.0
    } else {
        interval_sec
    };
    if packets.is_empty() {
        return Vec::new();
    }
    let max_rel = packets
        .iter()
        .map(|p| p.summary.rel_time_sec)
        .fold(0.0_f64, f64::max);
    let num_buckets = ((max_rel / interval).floor() as usize + 1).min(100_000);
    let mut buckets: Vec<IoGraphBucket> = (0..num_buckets)
        .map(|i| IoGraphBucket {
            start_sec: (i as f64) * interval,
            end_sec: ((i + 1) as f64) * interval,
            packets: 0,
            bytes: 0,
            bits_per_sec: 0.0,
        })
        .collect();

    for pkt in packets {
        let idx = ((pkt.summary.rel_time_sec / interval).floor() as usize)
            .min(buckets.len().saturating_sub(1));
        if let Some(b) = buckets.get_mut(idx) {
            b.packets += 1;
            b.bytes += pkt.summary.length as u64;
        }
    }

    for b in &mut buckets {
        b.bits_per_sec = ((b.bytes as f64) * 8.0) / interval;
    }
    buckets
}

/// Exported HTTP object metadata and payload (`STA-06`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedObject {
    pub frame_number: u64,
    pub hostname: String,
    pub content_type: String,
    pub filename: String,
    pub data: Vec<u8>,
}

/// Sanitize an untrusted URI or header filename to prevent directory traversal (`../`, `\`, `:`, null bytes, Windows reserved device names) (`STA-06`, `REL-03`).
pub fn sanitize_export_filename(raw_uri: &str, fallback_index: usize) -> String {
    let without_query = raw_uri.split('?').next().unwrap_or(raw_uri);
    let last_segment = without_query
        .rsplit(['/', '\\'])
        .find(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .unwrap_or("");

    let cleaned: String = last_segment
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();

    let trimmed = cleaned.trim_start_matches('.');
    let upper = trimmed
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    let is_windows_reserved = matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "LPT1"
            | "LPT2"
            | "LPT3"
    );

    if trimmed.is_empty() || is_windows_reserved {
        format!("object_{fallback_index}.bin")
    } else {
        trimmed.chars().take(120).collect()
    }
}

/// Extract HTTP objects from dissected packets (`STA-06`).
pub fn extract_http_objects(
    _frames: &[Frame],
    packets: &[DissectedPacket],
) -> Vec<ExportedObject> {
    let mut objects = Vec::new();
    let mut stream_uris: HashMap<u64, (String, String)> = HashMap::new();

    for pkt in packets {
        let stream_id = pkt
            .tree
            .by_abbrev("tcp.stream")
            .next()
            .and_then(|n| n.value.as_u64())
            .unwrap_or(0);

        if let Some(uri_node) = pkt.tree.by_abbrev("http.request.uri").next() {
            let host = pkt
                .tree
                .by_abbrev("http.host")
                .next()
                .map(|n| n.value.display_value())
                .unwrap_or_else(|| pkt.summary.destination.clone());
            stream_uris.insert(stream_id, (host, uri_node.value.display_value()));
        }

        if let Some(body_node) = pkt.tree.by_abbrev("http.file_data").next() {
            let Some(raw_bytes) = body_node.value.as_bytes() else {
                continue;
            };
            let content_type = pkt
                .tree
                .by_abbrev("http.content_type")
                .next()
                .map(|n| n.value.display_value())
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let encoding = pkt
                .tree
                .by_abbrev("http.content_encoding")
                .next()
                .map(|n| n.value.display_value())
                .unwrap_or_default();

            let payload =
                decompress_http_body(&encoding, raw_bytes).unwrap_or_else(|_| raw_bytes.to_vec());

            let (hostname, uri) = stream_uris
                .get(&stream_id)
                .cloned()
                .unwrap_or_else(|| (pkt.summary.source.clone(), String::new()));
            let filename = sanitize_export_filename(&uri, objects.len() + 1);

            objects.push(ExportedObject {
                frame_number: pkt.summary.number,
                hostname,
                content_type,
                filename,
                data: payload,
            });
        }
    }
    objects
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_export_filename_blocks_path_traversal_and_reserved_names() {
        assert_eq!(
            sanitize_export_filename("/../../etc/passwd?foo=bar", 1),
            "passwd"
        );
        assert_eq!(sanitize_export_filename("..\\..\\Windows\\win.ini", 2), "win.ini");
        assert_eq!(sanitize_export_filename("/CON.txt", 3), "object_3.bin");
        assert_eq!(sanitize_export_filename("/", 4), "object_4.bin");
    }
}
