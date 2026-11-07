use mash_core::{ExpertGroup, ExpertSeverity, FieldType, ProtocolId};
use mash_dissect::{
    DissectCtx, DissectResult, Dissector, Next, PacketCursor, Registry, TableId, TruncatedError,
};

/// RFC 9293 Transmission Control Protocol dissector (`tcp`).
pub struct TcpDissector {
    proto_id: ProtocolId,
}

impl TcpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Transmission Control Protocol", "TCP", "tcp")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "tcp.srcport", "Source Port", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "tcp.dstport",
            "Destination Port",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "tcp.stream", "Stream index", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "tcp.len", "TCP Segment Len", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "tcp.seq", "Sequence Number", FieldType::Uint32, "");
        let _ = reg.register_field(
            pid,
            "tcp.ack",
            "Acknowledgment Number",
            FieldType::Uint32,
            "",
        );
        let _ = reg.register_field(pid, "tcp.hdr_len", "Header Length", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "tcp.flags", "Flags", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "tcp.flags.cwr", "Congestion Window Reduced", FieldType::Bool, "");
        let _ = reg.register_field(pid, "tcp.flags.ece", "ECN-Echo", FieldType::Bool, "");
        let _ = reg.register_field(pid, "tcp.flags.urg", "Urgent", FieldType::Bool, "");
        let _ = reg.register_field(pid, "tcp.flags.ack", "Acknowledgment", FieldType::Bool, "");
        let _ = reg.register_field(pid, "tcp.flags.psh", "Push", FieldType::Bool, "");
        let _ = reg.register_field(pid, "tcp.flags.rst", "Reset", FieldType::Bool, "");
        let _ = reg.register_field(pid, "tcp.flags.syn", "Syn", FieldType::Bool, "");
        let _ = reg.register_field(pid, "tcp.flags.fin", "Fin", FieldType::Bool, "");
        let _ = reg.register_field(
            pid,
            "tcp.window_size_value",
            "Window",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "tcp.checksum", "Checksum", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "tcp.urgent_pointer",
            "Urgent Pointer",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tcp.options.mss_val",
            "MSS Value",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tcp.options.wscale.shift",
            "Shift count",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tcp.options.timestamp.tsval",
            "Timestamp value",
            FieldType::Uint32,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tcp.options.timestamp.tsecr",
            "Timestamp echo reply",
            FieldType::Uint32,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for TcpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (src_port, r_sport) = buf.read_u16_be()?;
        let (dst_port, r_dport) = buf.read_u16_be()?;
        let (seq, r_seq) = buf.read_u32_be()?;
        let (ack, r_ack) = buf.read_u32_be()?;
        let (off_flags, r_flags) = buf.read_u16_be()?;
        let (win, r_win) = buf.read_u16_be()?;
        let (csum, r_csum) = buf.read_u16_be()?;
        let (urg, r_urg) = buf.read_u16_be()?;

        let hdr_len = (((off_flags >> 12) & 0x0f) as usize) * 4;
        if hdr_len < 20 {
            return Err(TruncatedError {
                offset: start + 12,
                needed: 20,
                available: hdr_len,
            });
        }

        let opts_len = hdr_len - 20;
        let (opts_bytes, r_opts) = buf.read_bytes(opts_len)?;
        let seg_len = buf.remaining() as u32;
        let hdr_range = buf.range_from(start);

        ctx.src_port = Some(src_port);
        ctx.dst_port = Some(dst_port);

        let src_ip = ctx.net_src_raw.clone().unwrap_or_default();
        let dst_ip = ctx.net_dst_raw.clone().unwrap_or_default();
        let stream_id = ctx
            .conversations
            .tcp_stream_index(&src_ip, src_port, &dst_ip, dst_port);
        ctx.stream_id = Some(stream_id);

        let src_port_disp = ctx.resolver.format_tcp_port(src_port);
        let dst_port_disp = ctx.resolver.format_tcp_port(dst_port);

        let flags_u9 = off_flags & 0x01ff;
        let f_cwr = (flags_u9 & 0x80) != 0;
        let f_ece = (flags_u9 & 0x40) != 0;
        let f_urg = (flags_u9 & 0x20) != 0;
        let f_ack = (flags_u9 & 0x10) != 0;
        let f_psh = (flags_u9 & 0x08) != 0;
        let f_rst = (flags_u9 & 0x04) != 0;
        let f_syn = (flags_u9 & 0x02) != 0;
        let f_fin = (flags_u9 & 0x01) != 0;

        let mut flag_names = Vec::new();
        if f_syn {
            flag_names.push("SYN");
        }
        if f_fin {
            flag_names.push("FIN");
        }
        if f_rst {
            flag_names.push("RST");
        }
        if f_psh {
            flag_names.push("PSH");
        }
        if f_ack {
            flag_names.push("ACK");
        }
        if f_urg {
            flag_names.push("URG");
        }
        if f_ece {
            flag_names.push("ECE");
        }
        if f_cwr {
            flag_names.push("CWR");
        }
        let flags_str = flag_names.join(", ");

        let root = ctx.begin_protocol(
            self.proto_id,
            format!(
                "Transmission Control Protocol, Src Port: {src_port_disp}, Dst Port: {dst_port_disp}, Seq: {seq}, Ack: {ack}, Len: {seg_len}"
            ),
            hdr_range,
        );
        ctx.add_u64(Some(root), "tcp.srcport", src_port as u64, r_sport, None);
        ctx.add_u64(Some(root), "tcp.dstport", dst_port as u64, r_dport, None);
        ctx.add_generated_u64(Some(root), "tcp.stream", stream_id as u64, hdr_range, None);
        ctx.add_generated_u64(Some(root), "tcp.len", seg_len as u64, hdr_range, None);
        ctx.add_u64(Some(root), "tcp.seq", seq as u64, r_seq, None);
        ctx.add_u64(Some(root), "tcp.ack", ack as u64, r_ack, None);
        ctx.add_u64(
            Some(root),
            "tcp.hdr_len",
            hdr_len as u64,
            mash_core::ByteRange::with_source(r_flags.source_idx, r_flags.start, r_flags.start + 1)
                .with_bitmask(0xf0),
            Some(format!("Header Length: {hdr_len} bytes ({})", hdr_len / 4)),
        );

        let flags_node = ctx.add_u64(
            Some(root),
            "tcp.flags",
            flags_u9 as u64,
            r_flags.with_bitmask(0x0fff),
            Some(format!("Flags: 0x{flags_u9:03x} ({flags_str})")),
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.cwr",
            f_cwr,
            r_flags.with_bitmask(0x0080),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.ece",
            f_ece,
            r_flags.with_bitmask(0x0040),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.urg",
            f_urg,
            r_flags.with_bitmask(0x0020),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.ack",
            f_ack,
            r_flags.with_bitmask(0x0010),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.psh",
            f_psh,
            r_flags.with_bitmask(0x0008),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.rst",
            f_rst,
            r_flags.with_bitmask(0x0004),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.syn",
            f_syn,
            r_flags.with_bitmask(0x0002),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "tcp.flags.fin",
            f_fin,
            r_flags.with_bitmask(0x0001),
            None,
        );

        if f_syn && !f_ack {
            ctx.add_expert(
                flags_node,
                ExpertSeverity::Chat,
                ExpertGroup::Sequence,
                "Connection establish request (SYN)".to_string(),
                r_flags,
            );
        } else if f_syn && f_ack {
            ctx.add_expert(
                flags_node,
                ExpertSeverity::Chat,
                ExpertGroup::Sequence,
                "Connection establish acknowledge (SYN+ACK)".to_string(),
                r_flags,
            );
        } else if f_rst {
            ctx.add_expert(
                flags_node,
                ExpertSeverity::Warn,
                ExpertGroup::Sequence,
                "Connection reset (RST)".to_string(),
                r_flags,
            );
        }

        ctx.add_u64(Some(root), "tcp.window_size_value", win as u64, r_win, None);
        ctx.add_u64(
            Some(root),
            "tcp.checksum",
            csum as u64,
            r_csum,
            Some(format!("Checksum: 0x{csum:04x}")),
        );
        ctx.add_u64(Some(root), "tcp.urgent_pointer", urg as u64, r_urg, None);

        // Parse TCP options TLV
        let mut opt_summary = Vec::new();
        let mut i = 0usize;
        while i < opts_bytes.len() {
            let kind = opts_bytes[i];
            if kind == 0 {
                break; // End of Option List
            }
            if kind == 1 {
                i += 1; // NOP
                continue;
            }
            if i + 1 >= opts_bytes.len() {
                break;
            }
            let len = opts_bytes[i + 1] as usize;
            if len < 2 || i + len > opts_bytes.len() {
                break;
            }
            let val = &opts_bytes[i + 2..i + len];
            match kind {
                2 if val.len() == 2 => {
                    let mss = u16::from_be_bytes([val[0], val[1]]);
                    ctx.add_u64(Some(root), "tcp.options.mss_val", mss as u64, r_opts, None);
                    opt_summary.push(format!("MSS={mss}"));
                }
                3 if val.len() == 1 => {
                    let ws = val[0];
                    ctx.add_u64(
                        Some(root),
                        "tcp.options.wscale.shift",
                        ws as u64,
                        r_opts,
                        None,
                    );
                    opt_summary.push(format!("WS={}", 1u32 << (ws.min(14))));
                }
                4 => {
                    opt_summary.push("SACK_PERM".to_string());
                }
                8 if val.len() == 8 => {
                    let tsval = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                    let tsecr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
                    ctx.add_u64(
                        Some(root),
                        "tcp.options.timestamp.tsval",
                        tsval as u64,
                        r_opts,
                        None,
                    );
                    ctx.add_u64(
                        Some(root),
                        "tcp.options.timestamp.tsecr",
                        tsecr as u64,
                        r_opts,
                        None,
                    );
                    opt_summary.push(format!("TSval={tsval} TSecr={tsecr}"));
                }
                _ => {}
            }
            i += len;
        }

        let opts_tail = if opt_summary.is_empty() {
            String::new()
        } else {
            format!(" {}", opt_summary.join(" "))
        };
        ctx.set_info(format!(
            "{src_port_disp} -> {dst_port_disp} [{flags_str}] Seq={seq} Ack={ack} Win={win} Len={seg_len}{opts_tail}"
        ));

        if seg_len == 0 {
            Ok(Next::None)
        } else {
            Ok(Next::Ports {
                table: TableId::TcpPort,
                src_port,
                dst_port,
            })
        }
    }
}

/// RFC 768 User Datagram Protocol dissector (`udp`).
pub struct UdpDissector {
    proto_id: ProtocolId,
}

impl UdpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("User Datagram Protocol", "UDP", "udp")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "udp.srcport", "Source Port", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "udp.dstport",
            "Destination Port",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "udp.length", "Length", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "udp.checksum", "Checksum", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "udp.stream", "Stream index", FieldType::Uint32, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for UdpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (src_port, r_sport) = buf.read_u16_be()?;
        let (dst_port, r_dport) = buf.read_u16_be()?;
        let (udp_len, r_len) = buf.read_u16_be()?;
        let (csum, r_csum) = buf.read_u16_be()?;
        let hdr_range = buf.range_from(start);

        ctx.src_port = Some(src_port);
        ctx.dst_port = Some(dst_port);

        let src_ip = ctx.net_src_raw.clone().unwrap_or_default();
        let dst_ip = ctx.net_dst_raw.clone().unwrap_or_default();
        let stream_id = ctx
            .conversations
            .udp_stream_index(&src_ip, src_port, &dst_ip, dst_port);
        ctx.stream_id = Some(stream_id);

        let src_disp = ctx.resolver.format_udp_port(src_port);
        let dst_disp = ctx.resolver.format_udp_port(dst_port);

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("User Datagram Protocol, Src Port: {src_disp}, Dst Port: {dst_disp}"),
            hdr_range,
        );
        ctx.add_u64(Some(root), "udp.srcport", src_port as u64, r_sport, None);
        ctx.add_u64(Some(root), "udp.dstport", dst_port as u64, r_dport, None);
        ctx.add_u64(Some(root), "udp.length", udp_len as u64, r_len, None);
        ctx.add_u64(
            Some(root),
            "udp.checksum",
            csum as u64,
            r_csum,
            Some(format!("Checksum: 0x{csum:04x}")),
        );
        ctx.add_generated_u64(Some(root), "udp.stream", stream_id as u64, hdr_range, None);

        let payload_len = (udp_len as usize).saturating_sub(8);
        ctx.set_info(format!("{src_disp} -> {dst_disp} Len={payload_len}"));

        if buf.is_empty() {
            Ok(Next::None)
        } else {
            Ok(Next::Ports {
                table: TableId::UdpPort,
                src_port,
                dst_port,
            })
        }
    }
}

/// RFC 7348 Virtual eXtensible Local Area Network (`vxlan`, UDP 4789).
pub struct VxlanDissector {
    proto_id: ProtocolId,
    eth_proto_id: ProtocolId,
}

impl VxlanDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol(
                "Virtual eXtensible Local Area Network",
                "VXLAN",
                "vxlan",
            )
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "vxlan.flags", "Flags", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "vxlan.vni",
            "VXLAN Network Identifier (VNI)",
            FieldType::Uint24,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId, eth_proto_id: ProtocolId) -> Self {
        Self {
            proto_id,
            eth_proto_id,
        }
    }
}

impl Dissector for VxlanDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (flags, r_flags) = buf.read_u8()?;
        let _ = buf.read_u24_be()?;
        let (vni, r_vni) = buf.read_u24_be()?;
        let _ = buf.read_u8()?;
        let hdr_range = buf.range_from(start);

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Virtual eXtensible Local Area Network, VNI: {vni}"),
            hdr_range,
        );
        ctx.add_u64(Some(root), "vxlan.flags", flags as u64, r_flags, None);
        ctx.add_u64(Some(root), "vxlan.vni", vni as u64, r_vni, None);

        Ok(Next::Dissector(self.eth_proto_id))
    }
}

