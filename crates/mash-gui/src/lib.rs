pub mod app;

use mash_ai::AiEngine;
use mash_core::{
    ByteRange, DissectedPacket, Frame, NameResolver, NodeId, ResolutionConfig, Result,
};
use mash_dissect::{ConversationTracker, DissectorEngine};
use mash_filter::{autocomplete_filter, CompiledFilter, FilterDiagnostic};
use mash_pcapfile::{read_capture_file, CaptureFile};
use mash_protocols::build_default_engine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// RGB color tuple (`GUI-05`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RgbColor(pub u8, pub u8, pub u8);

/// Ordered packet list coloring rule (`GUI-05`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColoringRule {
    pub name: String,
    pub filter_expr: String,
    pub fg: RgbColor,
    pub bg: RgbColor,
    pub enabled: bool,
}

/// Built-in default packet coloring rules (`GUI-05`).
pub fn default_coloring_rules() -> Vec<ColoringRule> {
    vec![
        ColoringRule {
            name: "TCP RST".to_string(),
            filter_expr: "tcp.flags.rst == true".to_string(),
            fg: RgbColor(255, 255, 255),
            bg: RgbColor(164, 0, 0),
            enabled: true,
        },
        ColoringRule {
            name: "HTTP Server Error".to_string(),
            filter_expr: "http.response.code >= 400".to_string(),
            fg: RgbColor(255, 220, 220),
            bg: RgbColor(120, 20, 20),
            enabled: true,
        },
        ColoringRule {
            name: "DNS Error".to_string(),
            filter_expr: "dns.flags.rcode != 0".to_string(),
            fg: RgbColor(255, 235, 180),
            bg: RgbColor(110, 70, 0),
            enabled: true,
        },
        ColoringRule {
            name: "TCP SYN / FIN".to_string(),
            filter_expr: "tcp.flags.syn == true || tcp.flags.fin == true".to_string(),
            fg: RgbColor(220, 255, 220),
            bg: RgbColor(30, 80, 45),
            enabled: true,
        },
        ColoringRule {
            name: "HTTP".to_string(),
            filter_expr: "http".to_string(),
            fg: RgbColor(225, 255, 225),
            bg: RgbColor(25, 65, 35),
            enabled: true,
        },
        ColoringRule {
            name: "TLS".to_string(),
            filter_expr: "tls".to_string(),
            fg: RgbColor(225, 230, 255),
            bg: RgbColor(35, 40, 85),
            enabled: true,
        },
        ColoringRule {
            name: "TCP".to_string(),
            filter_expr: "tcp".to_string(),
            fg: RgbColor(230, 240, 255),
            bg: RgbColor(28, 45, 68),
            enabled: true,
        },
        ColoringRule {
            name: "UDP".to_string(),
            filter_expr: "udp".to_string(),
            fg: RgbColor(220, 245, 255),
            bg: RgbColor(20, 55, 75),
            enabled: true,
        },
        ColoringRule {
            name: "ARP".to_string(),
            filter_expr: "arp".to_string(),
            fg: RgbColor(255, 245, 215),
            bg: RgbColor(70, 60, 25),
            enabled: true,
        },
        ColoringRule {
            name: "ICMP".to_string(),
            filter_expr: "icmp || icmpv6".to_string(),
            fg: RgbColor(245, 225, 255),
            bg: RgbColor(60, 30, 75),
            enabled: true,
        },
    ]
}

/// Filter bar validation status (`GUI-04`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterBarStatus {
    Empty,
    Valid,
    Invalid(FilterDiagnostic),
}

/// Saved user configuration profile (`GUI-07`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceProfile {
    pub name: String,
    pub columns: Vec<String>,
    pub coloring_rules: Vec<ColoringRule>,
    pub resolution: ResolutionConfig,
}

impl Default for WorkspaceProfile {
    fn default() -> Self {
        Self {
            name: "Default".to_string(),
            columns: vec![
                "No.".to_string(),
                "Time".to_string(),
                "Source".to_string(),
                "Destination".to_string(),
                "Protocol".to_string(),
                "Length".to_string(),
                "Info".to_string(),
            ],
            coloring_rules: default_coloring_rules(),
            resolution: ResolutionConfig::default(),
        }
    }
}

/// Three-Pane synchronized analyzer state (`GUI-01`..`GUI-10`).
pub struct AnalyzerWorkspace {
    pub engine: DissectorEngine,
    pub ai: AiEngine,
    pub profile: WorkspaceProfile,
    pub frames: Vec<Frame>,
    pub dissected: Vec<DissectedPacket>,
    /// Indices into `dissected` matching the active display filter.
    pub filtered_indices: Vec<usize>,
    pub filter_input: String,
    pub filter_status: FilterBarStatus,
    /// Currently selected 1-based frame number in Pane 1.
    pub selected_frame: Option<u64>,
    /// Currently selected `NodeId` in Pane 2 (Packet Details tree).
    pub selected_node: Option<NodeId>,
    /// Expanded `NodeId`s in Pane 2 for the active packet.
    pub expanded_nodes: HashSet<NodeId>,
    /// Expanded protocol/field abbreviations persisted across packets in Pane 2.
    pub expanded_abbrevs: HashSet<String>,
    /// Active data source tab in Pane 3 (0 = Frame, 1+ = Secondary DataSource).
    pub active_source_tab: u8,
    /// Highlighted byte range in Pane 3 (`GUI-02` bidirectional sync).
    pub highlighted_bytes: Option<ByteRange>,
    compiled_coloring: Vec<(ColoringRule, CompiledFilter)>,
}

impl Default for AnalyzerWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzerWorkspace {
    pub fn new() -> Self {
        let engine = build_default_engine();
        let profile = WorkspaceProfile::default();
        let default_expanded: HashSet<String> = [
            "arp", "icmp", "icmpv6", "dns", "dhcp", "dhcpv6", "http", "tls", "quic", "ntp", "bgp",
            "ospf", "mqtt", "modbus", "smb2", "grpc",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mut ws = Self {
            engine,
            ai: AiEngine::default_local(),
            profile,
            frames: Vec::new(),
            dissected: Vec::new(),
            filtered_indices: Vec::new(),
            filter_input: String::new(),
            filter_status: FilterBarStatus::Empty,
            selected_frame: None,
            selected_node: None,
            expanded_nodes: HashSet::new(),
            expanded_abbrevs: default_expanded,
            active_source_tab: 0,
            highlighted_bytes: None,
            compiled_coloring: Vec::new(),
        };
        ws.recompile_coloring_rules();
        ws
    }

    pub fn recompile_coloring_rules(&mut self) {
        self.compiled_coloring.clear();
        for rule in &self.profile.coloring_rules {
            if rule.enabled {
                if let Ok(cf) =
                    CompiledFilter::compile(&rule.filter_expr, Some(&self.engine.registry))
                {
                    self.compiled_coloring.push((rule.clone(), cf));
                }
            }
        }
    }

    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let cap = read_capture_file(path)?;
        self.load_capture(cap);
        Ok(())
    }

    pub fn load_capture(&mut self, mut cap: CaptureFile) {
        for (idx, frame) in cap.frames.iter_mut().enumerate() {
            frame.number = (idx + 1) as u64;
        }
        self.frames = cap.frames;
        self.selected_frame = None;
        self.selected_node = None;
        self.expanded_nodes.clear();
        self.active_source_tab = 0;
        self.highlighted_bytes = None;
        self.redissect_all();
    }

    pub fn redissect_all(&mut self) {
        let mut resolver = NameResolver::new(self.profile.resolution);
        let mut conv = ConversationTracker::new();
        self.dissected.clear();

        let mut ref_ts = self.frames.first().map(|f| f.timestamp);
        let mut prev_ts = None;

        for frame in &self.frames {
            if frame.flags.time_reference {
                ref_ts = Some(frame.timestamp);
            }
            let mut pkt =
                self.engine
                    .dissect_frame(frame, ref_ts, prev_ts, &mut resolver, &mut conv);
            if frame.flags.time_reference {
                pkt.summary.info = format!("*REF* {}", pkt.summary.info);
            }
            prev_ts = Some(frame.timestamp);
            self.dissected.push(pkt);
        }

        let _ = mash_stats::analyze_tcp_flows(&mut self.dissected);
        let current_filter = self.filter_input.clone();
        self.set_display_filter(&current_filter);
    }

    /// Update the live display filter bar, validating syntax and updating `filtered_indices` (`GUI-04`).
    pub fn set_display_filter(&mut self, expr: &str) {
        self.filter_input = expr.to_string();
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            self.filter_status = FilterBarStatus::Empty;
            self.filtered_indices = (0..self.dissected.len())
                .filter(|&i| !self.frames[i].flags.ignored)
                .collect();
        } else {
            match CompiledFilter::compile(trimmed, Some(&self.engine.registry)) {
                Ok(cf) => {
                    self.filter_status = FilterBarStatus::Valid;
                    self.filtered_indices = self
                        .dissected
                        .iter()
                        .enumerate()
                        .filter(|&(i, pkt)| !self.frames[i].flags.ignored && cf.matches(pkt))
                        .map(|(i, _)| i)
                        .collect();
                }
                Err(diag) => {
                    self.filter_status = FilterBarStatus::Invalid(diag);
                    return;
                }
            }
        }

        // Ensure `selected_frame` points to a currently visible packet
        let sel_visible = self.selected_frame.is_some_and(|fno| {
            let idx = (fno.saturating_sub(1)) as usize;
            self.filtered_indices.contains(&idx)
        });
        if !sel_visible {
            if let Some(&first_idx) = self.filtered_indices.first() {
                let fno = self.dissected[first_idx].summary.number;
                self.select_frame(fno);
            } else {
                self.selected_frame = None;
                self.selected_node = None;
                self.highlighted_bytes = None;
            }
        }
    }

    pub fn is_node_expanded(&self, node_id: NodeId, abbrev: &str) -> bool {
        self.expanded_nodes.contains(&node_id) || self.expanded_abbrevs.contains(abbrev)
    }

    pub fn toggle_node_expanded(&mut self, node_id: NodeId, abbrev: &str) {
        if self.is_node_expanded(node_id, abbrev) {
            self.expanded_nodes.remove(&node_id);
            self.expanded_abbrevs.remove(abbrev);
        } else {
            self.expanded_nodes.insert(node_id);
            self.expanded_abbrevs.insert(abbrev.to_string());
        }
    }

    pub fn expand_all_nodes(&mut self) {
        if let Some(fno) = self.selected_frame {
            if let Some(pkt) = self.dissected.get((fno - 1) as usize) {
                for n in &pkt.tree.nodes {
                    if !n.children.is_empty() {
                        self.expanded_nodes.insert(n.id);
                        self.expanded_abbrevs.insert(n.abbrev.clone());
                    }
                }
            }
        }
    }

    pub fn collapse_all_nodes(&mut self) {
        self.expanded_nodes.clear();
        self.expanded_abbrevs.clear();
    }

    pub fn select_next_displayed_frame(&mut self) -> Option<u64> {
        if self.filtered_indices.is_empty() {
            return None;
        }
        let next_idx = if let Some(cur_fno) = self.selected_frame {
            let cur_vec_idx = (cur_fno.saturating_sub(1)) as usize;
            if let Some(pos) = self.filtered_indices.iter().position(|&i| i == cur_vec_idx) {
                self.filtered_indices[(pos + 1).min(self.filtered_indices.len() - 1)]
            } else {
                self.filtered_indices[0]
            }
        } else {
            self.filtered_indices[0]
        };
        let fno = self.dissected.get(next_idx)?.summary.number;
        self.select_frame(fno);
        Some(fno)
    }

    pub fn select_prev_displayed_frame(&mut self) -> Option<u64> {
        if self.filtered_indices.is_empty() {
            return None;
        }
        let prev_idx = if let Some(cur_fno) = self.selected_frame {
            let cur_vec_idx = (cur_fno.saturating_sub(1)) as usize;
            if let Some(pos) = self.filtered_indices.iter().position(|&i| i == cur_vec_idx) {
                self.filtered_indices[pos.saturating_sub(1)]
            } else {
                self.filtered_indices[0]
            }
        } else {
            self.filtered_indices[0]
        };
        let fno = self.dissected.get(prev_idx)?.summary.number;
        self.select_frame(fno);
        Some(fno)
    }

    pub fn select_first_displayed_frame(&mut self) -> Option<u64> {
        let &first_idx = self.filtered_indices.first()?;
        let fno = self.dissected.get(first_idx)?.summary.number;
        self.select_frame(fno);
        Some(fno)
    }

    pub fn select_last_displayed_frame(&mut self) -> Option<u64> {
        let &last_idx = self.filtered_indices.last()?;
        let fno = self.dissected.get(last_idx)?.summary.number;
        self.select_frame(fno);
        Some(fno)
    }

    pub fn autocomplete(&self, max_items: usize) -> Vec<String> {
        autocomplete_filter(&self.filter_input, &self.engine.registry, max_items)
    }

    /// Return a virtualized viewport slice of visible packets for O(1) 60fps scrolling (`GUI-02`, `PERF-03`).
    pub fn visible_packet_slice(
        &self,
        scroll_offset: usize,
        viewport_rows: usize,
    ) -> Vec<&DissectedPacket> {
        self.filtered_indices
            .iter()
            .skip(scroll_offset)
            .take(viewport_rows)
            .filter_map(|&idx| self.dissected.get(idx))
            .collect()
    }

    /// Evaluate coloring rules for a packet (`GUI-05`).
    pub fn color_for_packet(&self, pkt: &DissectedPacket) -> Option<(RgbColor, RgbColor)> {
        if let Some(frame) = self.frames.get((pkt.summary.number.saturating_sub(1)) as usize) {
            if frame.flags.marked {
                return Some((RgbColor(255, 255, 255), RgbColor(15, 25, 50)));
            }
        }
        for (rule, cf) in &self.compiled_coloring {
            if cf.matches(pkt) {
                return Some((rule.fg, rule.bg));
            }
        }
        None
    }

    /// Select a packet in Pane 1 (`GUI-02`).
    pub fn select_frame(&mut self, frame_number: u64) {
        if frame_number >= 1 && (frame_number as usize) <= self.dissected.len() {
            self.selected_frame = Some(frame_number);
            self.selected_node = None;
            self.expanded_nodes.clear();
            self.active_source_tab = 0;
            self.highlighted_bytes = None;
        }
    }

    /// Select a field node in Pane 2 -> highlights its exact `ByteRange` in Pane 3 (`GUI-02`).
    pub fn select_field_node(&mut self, node_id: NodeId) {
        let Some(fno) = self.selected_frame else {
            return;
        };
        let Some(pkt) = self.dissected.get((fno - 1) as usize) else {
            return;
        };
        if let Some(node) = pkt.tree.node(node_id) {
            self.selected_node = Some(node_id);
            self.active_source_tab = node.byte_range.source_idx;
            self.highlighted_bytes = Some(node.byte_range);
        }
    }

    /// Click a byte offset in Pane 3 -> selects the deepest covering `FieldNode` in Pane 2 (`GUI-02`).
    pub fn select_byte_offset(&mut self, source_idx: u8, byte_offset: usize) -> Option<NodeId> {
        let fno = self.selected_frame?;
        let pkt = self.dissected.get((fno - 1) as usize)?;
        let node = pkt.tree.deepest_node_at_offset(source_idx, byte_offset)?;
        let nid = node.id;
        let range = node.byte_range;
        // Expand ancestor chain so the selected node is visible in Pane 2
        let mut curr = node.parent;
        while let Some(pid) = curr {
            self.expanded_nodes.insert(pid);
            if let Some(parent_node) = pkt.tree.node(pid) {
                self.expanded_abbrevs.insert(parent_node.abbrev.clone());
                curr = parent_node.parent;
            } else {
                curr = None;
            }
        }
        self.selected_node = Some(nid);
        self.active_source_tab = source_idx;
        self.highlighted_bytes = Some(range);
        Some(nid)
    }

    /// Generate a display filter expression from the currently selected field node (`Apply as Filter`, `GUI-02`).
    pub fn filter_from_selected_node(&self) -> Option<String> {
        let fno = self.selected_frame?;
        let nid = self.selected_node?;
        let pkt = self.dissected.get((fno - 1) as usize)?;
        let node = pkt.tree.node(nid)?;
        if node.value == mash_core::FieldValue::None {
            Some(node.abbrev.clone())
        } else if matches!(node.value, mash_core::FieldValue::Str(_)) {
            Some(format!("{} == \"{}\"", node.abbrev, node.value.display_value()))
        } else {
            Some(format!("{} == {}", node.abbrev, node.value.display_value()))
        }
    }

    /// Toggle packet mark (`Ctrl+M` / `GUI-06`).
    pub fn toggle_mark_frame(&mut self, frame_number: u64) {
        if let Some(f) = self.frames.get_mut((frame_number.saturating_sub(1)) as usize) {
            f.flags.marked = !f.flags.marked;
        }
    }

    /// Toggle packet ignore (`Ctrl+D` / `GUI-06`).
    pub fn toggle_ignore_frame(&mut self, frame_number: u64) {
        if let Some(f) = self.frames.get_mut((frame_number.saturating_sub(1)) as usize) {
            f.flags.ignored = !f.flags.ignored;
        }
        let current = self.filter_input.clone();
        self.set_display_filter(&current);
    }

    /// Toggle time reference (`Ctrl+T` / `GUI-06`).
    pub fn toggle_time_reference(&mut self, frame_number: u64) {
        if let Some(f) = self.frames.get_mut((frame_number.saturating_sub(1)) as usize) {
            f.flags.time_reference = !f.flags.time_reference;
        }
        self.redissect_all();
    }

    /// Render a text-based 3-pane snapshot of the workspace (for terminal inspection and headless UI tests).
    pub fn render_three_pane_snapshot(&self, max_list_rows: usize) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "=== MUNG-ASH Workspace [Profile: {} | Filter: '{}' ({:?}) | Showing {}/{} packets] ===\n",
            self.profile.name,
            self.filter_input,
            self.filter_status,
            self.filtered_indices.len(),
            self.dissected.len()
        ));

        out.push_str("--- PANE 1: PACKET LIST ---\n");
        for pkt in self.visible_packet_slice(0, max_list_rows) {
            let marker = if self.selected_frame == Some(pkt.summary.number) {
                ">"
            } else {
                " "
            };
            out.push_str(&format!(
                "{marker} {:>4} {:>10.6} {:>16} -> {:<16} {:<6} {:>5} {}\n",
                pkt.summary.number,
                pkt.summary.rel_time_sec,
                pkt.summary.source,
                pkt.summary.destination,
                pkt.summary.protocol,
                pkt.summary.length,
                pkt.summary.info
            ));
        }

        if let Some(fno) = self.selected_frame {
            if let Some(pkt) = self.dissected.get((fno - 1) as usize) {
                out.push_str(&format!("--- PANE 2: PACKET DETAILS (Frame #{fno}) ---\n"));
                for &root_id in &pkt.tree.roots {
                    if let Some(node) = pkt.tree.node(root_id) {
                        let sel = if self.selected_node == Some(root_id) {
                            "*"
                        } else {
                            "+"
                        };
                        out.push_str(&format!("  {sel} {}\n", node.label));
                        for &cid in &node.children {
                            if let Some(ch) = pkt.tree.node(cid) {
                                let csel = if self.selected_node == Some(cid) {
                                    "*"
                                } else {
                                    "-"
                                };
                                out.push_str(&format!("      {csel} {}\n", ch.label));
                            }
                        }
                    }
                }

                out.push_str(&format!(
                    "--- PANE 3: PACKET BYTES (Source Tab #{}, Highlight: {:?}) ---\n",
                    self.active_source_tab, self.highlighted_bytes
                ));
                if let Some(frame) = self.frames.get((fno - 1) as usize) {
                    if let Some(bytes) = frame.source_bytes(self.active_source_tab) {
                        for (idx, chunk) in bytes.chunks(16).take(8).enumerate() {
                            let off = idx * 16;
                            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                            out.push_str(&format!("  {off:04x}  {}\n", hex.join(" ")));
                        }
                    }
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mash_core::{LinkType, Timestamp};
    use mash_pcapfile::CaptureFormat;

    #[test]
    fn three_pane_bidirectional_sync_and_time_reference() {
        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.extend_from_slice(&[0x45, 0x00, 0x00, 28, 0, 1, 0, 0, 64, 17, 0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        pkt.extend_from_slice(&53000u16.to_be_bytes());
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());

        cap.frames.push(Frame::new(
            1,
            Timestamp::from_secs_nanos(100, 0),
            LinkType::Ethernet,
            pkt.clone(),
        ));
        cap.frames.push(Frame::new(
            2,
            Timestamp::from_secs_nanos(105, 0),
            LinkType::Ethernet,
            pkt,
        ));

        let mut ws = AnalyzerWorkspace::new();
        ws.load_capture(cap);
        assert_eq!(ws.selected_frame, Some(1));

        // Clicking byte offset 27 (inside IPv4 Source Address 26..30) selects `ip.src` in Pane 2
        let nid = ws.select_byte_offset(0, 27).unwrap();
        assert_eq!(ws.highlighted_bytes, Some(ByteRange::new(26, 30)));
        assert_eq!(
            ws.filter_from_selected_node().as_deref(),
            Some("ip.src == 10.0.0.1")
        );
        let _ = nid;

        // Setting Time Reference on Frame 2 makes Frame 2's relative time 0.0
        ws.toggle_time_reference(2);
        assert!((ws.dissected[1].summary.rel_time_sec - 0.0).abs() < 1e-9);
    }

    #[test]
    fn unified_all_in_one_gui_app_state() {
        let ws = AnalyzerWorkspace::new();
        let mut app = crate::app::MashGuiApp::new(ws);
        assert_eq!(app.ws.frames.len(), 14);
        assert!(!app.tcp_streams.is_empty());
        assert!(!app.udp_streams.is_empty());

        // Verify IPv4 checksums in showcase capture are valid ("Good")
        let pkt3 = &app.ws.dissected[2];
        let csum_status = pkt3
            .tree
            .by_abbrev("ip.checksum.status")
            .next()
            .map(|n| n.value.display_value());
        assert_eq!(csum_status.as_deref(), Some("Good"));

        // Verify filtering to "http" automatically jumps `selected_frame` to Frame #8 (first HTTP packet)
        app.ws.set_display_filter("http");
        assert_eq!(app.ws.selected_frame, Some(8));
        assert_eq!(app.ws.select_next_displayed_frame(), Some(9));
        assert_eq!(app.ws.select_prev_displayed_frame(), Some(8));

        // Verify clicking TCP flags byte offset 47 selects `tcp.flags` (not `tcp.flags.fin`)
        let nid = app.ws.select_byte_offset(0, 47).unwrap();
        let selected_abbrev = app.ws.dissected[7]
            .tree
            .node(nid)
            .map(|n| n.abbrev.as_str());
        assert_eq!(selected_abbrev, Some("tcp.flags"));

        // Verify deterministic tree node expansion toggle
        assert!(app.ws.is_node_expanded(NodeId(0), "dns"));
        assert!(!app.ws.is_node_expanded(NodeId(0), "eth"));
        app.ws.toggle_node_expanded(NodeId(0), "eth");
        assert!(app.ws.is_node_expanded(NodeId(0), "eth"));

        // Verify live interface capture produces 25 valid, non-malformed packets
        let live_frames = mash_capture::capture_frames(&mash_capture::CaptureOptions {
            interfaces: vec!["eth0".to_string()],
            max_packets: Some(25),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(live_frames.len(), 25);
        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
        cap.frames = live_frames;
        app.ws.load_capture(cap);
        for pkt in &app.ws.dissected {
            assert!(
                !pkt.summary.info.contains("Malformed Packet"),
                "Unexpected malformed packet in live capture: {:?}",
                pkt.summary
            );
        }
    }
}
