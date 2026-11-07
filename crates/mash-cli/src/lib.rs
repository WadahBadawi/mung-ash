use mash_core::{DissectedPacket, FieldTree, Frame, NodeId, Timestamp};
use mash_pcapfile::CaptureFile;
use serde_json::json;
use std::collections::VecDeque;

/// Format a single-line packet summary (`CLI-01`).
pub fn format_summary_line(pkt: &DissectedPacket) -> String {
    format!(
        "{:>5} {:>12.6} {:>18} -> {:<18} {:<8} {:>5} {}",
        pkt.summary.number,
        pkt.summary.rel_time_sec,
        pkt.summary.source,
        pkt.summary.destination,
        pkt.summary.protocol,
        pkt.summary.length,
        pkt.summary.info
    )
}

/// Format the hierarchical `FieldTree` for `-V` verbose output (`CLI-01`).
pub fn format_tree_text(tree: &FieldTree) -> String {
    let mut out = String::new();
    for &root_id in &tree.roots {
        format_node_recursive(tree, root_id, 0, &mut out);
    }
    out
}

fn format_node_recursive(tree: &FieldTree, node_id: NodeId, depth: usize, out: &mut String) {
    let Some(node) = tree.node(node_id) else {
        return;
    };
    let indent = "    ".repeat(depth);
    out.push_str(&format!("{indent}{}\n", node.label));
    if let Some(exp) = &node.expert {
        out.push_str(&format!(
            "{indent}    [Expert Info ({}/{}): {}]\n",
            exp.severity.as_str(),
            exp.group.as_str(),
            exp.summary
        ));
    }
    for &child_id in &node.children {
        format_node_recursive(tree, child_id, depth + 1, out);
    }
}

/// Format a classic 16-byte-per-line hex + ASCII dump (`CLI-01 -x`, `EXP-03`).
pub fn format_hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (idx, chunk) in data.chunks(16).enumerate() {
        let off = idx * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..=0x7e).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{off:04x}  {:<47}   {ascii}\n", hex.join(" ")));
    }
    out
}

/// Format extracted `-T fields -e <field>` row (`EXP-02`).
pub fn format_fields_row(
    pkt: &DissectedPacket,
    fields: &[String],
    separator: &str,
    quote: Option<char>,
) -> String {
    let cols: Vec<String> = fields
        .iter()
        .map(|f| {
            let joined = pkt
                .tree
                .by_abbrev(f)
                .map(|n| n.value.display_value())
                .collect::<Vec<_>>()
                .join(",");
            match quote {
                Some(q) => format!("{q}{joined}{q}"),
                None => joined,
            }
        })
        .collect();
    cols.join(separator)
}

/// Export dissected packets as XML PDML (`-T pdml`, `EXP-02`).
pub fn export_pdml(packets: &[DissectedPacket]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<pdml version=\"0\" creator=\"mash\">\n");
    for pkt in packets {
        out.push_str("  <packet>\n");
        for &root_id in &pkt.tree.roots {
            if let Some(root) = pkt.tree.node(root_id) {
                out.push_str(&format!(
                    "    <proto name=\"{}\" showname=\"{}\" size=\"{}\" pos=\"{}\">\n",
                    xml_escape(&root.abbrev),
                    xml_escape(&root.label),
                    root.byte_range.len(),
                    root.byte_range.start
                ));
                for &child_id in &root.children {
                    if let Some(child) = pkt.tree.node(child_id) {
                        out.push_str(&format!(
                            "      <field name=\"{}\" showname=\"{}\" show=\"{}\" size=\"{}\" pos=\"{}\"/>\n",
                            xml_escape(&child.abbrev),
                            xml_escape(&child.label),
                            xml_escape(&child.value.display_value()),
                            child.byte_range.len(),
                            child.byte_range.start
                        ));
                    }
                }
                out.push_str("    </proto>\n");
            }
        }
        out.push_str("  </packet>\n");
    }
    out.push_str("</pdml>\n");
    out
}

/// Export dissected packets as XML PSML (`-T psml`, `EXP-02`).
pub fn export_psml(packets: &[DissectedPacket]) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<psml version=\"0\" creator=\"mash\">\n  <structure>\n    <section>No.</section>\n    <section>Time</section>\n    <section>Source</section>\n    <section>Destination</section>\n    <section>Protocol</section>\n    <section>Length</section>\n    <section>Info</section>\n  </structure>\n",
    );
    for pkt in packets {
        let s = &pkt.summary;
        out.push_str(&format!(
            "  <packet>\n    <section>{}</section>\n    <section>{:.6}</section>\n    <section>{}</section>\n    <section>{}</section>\n    <section>{}</section>\n    <section>{}</section>\n    <section>{}</section>\n  </packet>\n",
            s.number,
            s.rel_time_sec,
            xml_escape(&s.source),
            xml_escape(&s.destination),
            xml_escape(&s.protocol),
            s.length,
            xml_escape(&s.info)
        ));
    }
    out.push_str("</psml>\n");
    out
}

/// Export a single dissected packet in newline-delimited Elastic/EK JSON (`-T ek`, `EXP-02`).
pub fn export_ek_lines(pkt: &DissectedPacket) -> String {
    let index_line = json!({ "index": { "_index": "packets", "_type": "pcap_file" } });
    let mut layers = serde_json::Map::new();
    for node in &pkt.tree.nodes {
        if !node.abbrev.is_empty() && node.value != mash_core::FieldValue::None {
            layers.insert(
                node.abbrev.replace('.', "_"),
                json!(node.value.display_value()),
            );
        }
    }
    let doc_line = json!({
        "timestamp": pkt.summary.timestamp.nanos / 1_000_000,
        "layers": layers
    });
    format!("{index_line}\n{doc_line}\n")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Options for `mash-edit` (`CLI-03`).
#[derive(Debug, Clone, Default)]
pub struct EditOptions {
    pub snap_len: Option<u32>,
    pub time_shift_secs: Option<f64>,
    pub deduplicate_window: Option<usize>,
    pub frame_ranges: Vec<(u64, u64)>,
    pub comments: Vec<(u64, String)>,
}

/// Apply `EditOptions` to a `CaptureFile` (`CLI-03`).
pub fn apply_capture_edits(cap: &mut CaptureFile, opts: &EditOptions) {
    // 1. Filter by frame ranges if specified
    if !opts.frame_ranges.is_empty() {
        cap.frames.retain(|f| {
            opts.frame_ranges
                .iter()
                .any(|&(lo, hi)| f.number >= lo && f.number <= hi)
        });
    }

    // 2. Deduplicate over a sliding window of packet payloads
    if let Some(win) = opts.deduplicate_window {
        let window_size = win.max(1);
        let mut recent: VecDeque<Vec<u8>> = VecDeque::with_capacity(window_size);
        let mut kept: Vec<Frame> = Vec::with_capacity(cap.frames.len());
        for frame in cap.frames.drain(..) {
            if recent.iter().any(|prev| prev == &frame.data) {
                continue;
            }
            if recent.len() >= window_size {
                recent.pop_front();
            }
            recent.push_back(frame.data.clone());
            kept.push(frame);
        }
        cap.frames = kept;
    }

    // 3. Apply time shifts, snaplen slicing, comments, and renumber
    let shift_nanos = opts
        .time_shift_secs
        .map(|s| (s * 1_000_000_000.0) as i128)
        .unwrap_or(0);

    for (idx, frame) in cap.frames.iter_mut().enumerate() {
        let orig_no = frame.number;
        frame.number = (idx + 1) as u64;
        if shift_nanos != 0 {
            frame.timestamp = Timestamp::from_nanos(frame.timestamp.nanos.saturating_add(shift_nanos));
        }
        if let Some(snap) = opts.snap_len {
            if (frame.data.len() as u32) > snap {
                frame.data.truncate(snap as usize);
                frame.captured_len = snap;
            }
        }
        for (target_no, text) in &opts.comments {
            if *target_no == orig_no || *target_no == frame.number {
                frame.comments.push(text.clone());
            }
        }
    }
}

