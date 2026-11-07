use mash_core::{
    ip_protocol_name, ByteRange, ExpertGroup, ExpertSeverity, FieldType, ProtocolId,
};
use mash_dissect::{
    DissectCtx, DissectResult, Dissector, Next, PacketCursor, Registry, TableId, TruncatedError,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// RFC 826 Address Resolution Protocol dissector (`arp`).
pub struct ArpDissector {
    proto_id: ProtocolId,
}

impl ArpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Address Resolution Protocol", "ARP", "arp")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "arp.hw.type", "Hardware type", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "arp.proto.type",
            "Protocol type",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "arp.hw.size", "Hardware size", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "arp.proto.size",
            "Protocol size",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(pid, "arp.opcode", "Opcode", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "arp.src.hw_mac",
            "Sender MAC address",
            FieldType::MacAddr,
            "",
        );
        let _ = reg.register_field(
            pid,
            "arp.src.proto_ipv4",
            "Sender IP address",
            FieldType::Ipv4,
            "",
        );
        let _ = reg.register_field(
            pid,
            "arp.dst.hw_mac",
            "Target MAC address",
            FieldType::MacAddr,
            "",
        );
        let _ = reg.register_field(
            pid,
            "arp.dst.proto_ipv4",
            "Target IP address",
            FieldType::Ipv4,
            "",
        );
        let _ = reg.register_field(
            pid,
            "arp.isgratuitous",
            "Is gratuitous",
            FieldType::Bool,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for ArpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (htype, r_htype) = buf.read_u16_be()?;
        let (ptype, r_ptype) = buf.read_u16_be()?;
        let (hlen, r_hlen) = buf.read_u8()?;
        let (plen, r_plen) = buf.read_u8()?;
        let (opcode, r_op) = buf.read_u16_be()?;

        let op_name = match opcode {
            1 => "request",
            2 => "reply",
            3 => "RARP request",
            4 => "RARP reply",
            _ => "unknown",
        };

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Address Resolution Protocol ({op_name})"),
            buf.range_from(start),
        );
        ctx.add_u64(Some(root), "arp.hw.type", htype as u64, r_htype, None);
        ctx.add_u64(Some(root), "arp.proto.type", ptype as u64, r_ptype, None);
        ctx.add_u64(Some(root), "arp.hw.size", hlen as u64, r_hlen, None);
        ctx.add_u64(Some(root), "arp.proto.size", plen as u64, r_plen, None);
        ctx.add_u64(
            Some(root),
            "arp.opcode",
            opcode as u64,
            r_op,
            Some(format!("Opcode: {op_name} ({opcode})")),
        );

        if hlen == 6 && plen == 4 {
            let (sha, r_sha) = buf.read_mac()?;
            let (spa, r_spa) = buf.read_ipv4()?;
            let (tha, r_tha) = buf.read_mac()?;
            let (tpa, r_tpa) = buf.read_ipv4()?;
            let end_range = buf.range_from(start);
            ctx.update_node_range(root, end_range);

            let spa_str = Ipv4Addr::from(spa).to_string();
            let tpa_str = Ipv4Addr::from(tpa).to_string();
            let sha_str = ctx.resolver.format_mac(sha);

            ctx.add_mac(Some(root), "arp.src.hw_mac", sha, r_sha, None);
            ctx.add_ipv4(Some(root), "arp.src.proto_ipv4", spa, r_spa, None);
            ctx.add_mac(Some(root), "arp.dst.hw_mac", tha, r_tha, None);
            ctx.add_ipv4(Some(root), "arp.dst.proto_ipv4", tpa, r_tpa, None);

            let gratuitous = spa == tpa;
            if gratuitous {
                ctx.add_bool(Some(root), "arp.isgratuitous", true, end_range, None);
            }

            let info = match opcode {
                1 if gratuitous => format!("Gratuitous ARP for {spa_str} (Request)"),
                2 if gratuitous => format!("Gratuitous ARP for {spa_str} (Reply)"),
                1 => format!("Who has {tpa_str}? Tell {spa_str}"),
                2 => format!("{spa_str} is at {sha_str}"),
                _ => format!("ARP opcode {opcode} ({spa_str} -> {tpa_str})"),
            };
            ctx.set_info(info);
        }

        Ok(Next::None)
    }
}

/// RFC 791 Internet Protocol Version 4 dissector (`ip`).
pub struct Ipv4Dissector {
    proto_id: ProtocolId,
}

impl Ipv4Dissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Internet Protocol Version 4", "IPv4", "ip")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "ip.version", "Version", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ip.hdr_len", "Header Length", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "ip.dsfield",
            "Differentiated Services Field",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(pid, "ip.tos", "Type of Service", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ip.len", "Total Length", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "ip.id", "Identification", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "ip.flags", "Flags", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "ip.flags.df",
            "Don't fragment",
            FieldType::Bool,
            "",
        );
        let _ = reg.register_field(
            pid,
            "ip.flags.mf",
            "More fragments",
            FieldType::Bool,
            "",
        );
        let _ = reg.register_field(
            pid,
            "ip.frag_offset",
            "Fragment Offset",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "ip.ttl", "Time to Live", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ip.proto", "Protocol", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "ip.checksum",
            "Header Checksum",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "ip.checksum.status",
            "Header Checksum Status",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(pid, "ip.src", "Source Address", FieldType::Ipv4, "");
        let _ = reg.register_field(pid, "ip.dst", "Destination Address", FieldType::Ipv4, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

pub fn verify_ipv4_checksum(hdr: &[u8]) -> bool {
    if hdr.len() < 20 || !hdr.len().is_multiple_of(2) {
        return false;
    }
    let mut sum: u32 = 0;
    for &chunk in hdr.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(chunk) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum as u16) == 0xffff
}

impl Dissector for Ipv4Dissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let raw_slice = buf.slice_remaining();
        let (ver_ihl, r_ver) = buf.read_u8()?;
        let version = ver_ihl >> 4;
        let ihl_bytes = ((ver_ihl & 0x0f) as usize) * 4;
        if version != 4 || ihl_bytes < 20 {
            let root = ctx.begin_protocol(
                self.proto_id,
                format!("Internet Protocol Version {version} (Invalid IHL {ihl_bytes})"),
                r_ver,
            );
            ctx.add_expert(
                root,
                ExpertSeverity::Error,
                ExpertGroup::Malformed,
                format!("Invalid IPv4 header version={version} ihl={ihl_bytes}"),
                r_ver,
            );
            return Err(TruncatedError {
                offset: start,
                needed: 20,
                available: raw_slice.len(),
            });
        }

        let (tos, r_tos) = buf.read_u8()?;
        let (total_len, r_len) = buf.read_u16_be()?;
        let (ident, r_id) = buf.read_u16_be()?;
        let (flags_frag, r_ff) = buf.read_u16_be()?;
        let (ttl, r_ttl) = buf.read_u8()?;
        let (proto, r_proto) = buf.read_u8()?;
        let (csum, r_csum) = buf.read_u16_be()?;
        let (src, r_src) = buf.read_ipv4()?;
        let (dst, r_dst) = buf.read_ipv4()?;

        if ihl_bytes > 20 {
            let _ = buf.read_bytes(ihl_bytes - 20)?;
        }

        let hdr_range = ByteRange::with_source(buf.source_idx(), start, start + ihl_bytes);
        let src_raw = Ipv4Addr::from(src).to_string();
        let dst_raw = Ipv4Addr::from(dst).to_string();
        let src_disp = ctx.resolver.format_ipv4(src);
        let dst_disp = ctx.resolver.format_ipv4(dst);

        ctx.net_src_raw = Some(src_raw);
        ctx.net_dst_raw = Some(dst_raw);
        ctx.summary.source = src_disp.clone();
        ctx.summary.destination = dst_disp.clone();

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Internet Protocol Version 4, Src: {src_disp}, Dst: {dst_disp}"),
            hdr_range,
        );
        ctx.add_u64(
            Some(root),
            "ip.version",
            version as u64,
            r_ver.with_bitmask(0xf0),
            None,
        );
        ctx.add_u64(
            Some(root),
            "ip.hdr_len",
            ihl_bytes as u64,
            r_ver.with_bitmask(0x0f),
            Some(format!("Header Length: {ihl_bytes} bytes ({})", ver_ihl & 0x0f)),
        );
        ctx.add_u64(Some(root), "ip.dsfield", tos as u64, r_tos, None);
        ctx.add_u64(Some(root), "ip.tos", tos as u64, r_tos, None);
        ctx.add_u64(Some(root), "ip.len", total_len as u64, r_len, None);
        ctx.add_u64(
            Some(root),
            "ip.id",
            ident as u64,
            r_id,
            Some(format!("Identification: 0x{ident:04x} ({ident})")),
        );

        let flags_bits = (flags_frag >> 13) as u8;
        let df = (flags_bits & 0x02) != 0;
        let mf = (flags_bits & 0x01) != 0;
        let frag_offset = (flags_frag & 0x1fff) * 8;
        let flags_node = ctx.add_u64(
            Some(root),
            "ip.flags",
            flags_bits as u64,
            r_ff.with_bitmask(0xe000),
            Some(format!("Flags: 0x{flags_bits:02x}")),
        );
        ctx.add_bool(
            Some(flags_node),
            "ip.flags.df",
            df,
            r_ff.with_bitmask(0x4000),
            None,
        );
        ctx.add_bool(
            Some(flags_node),
            "ip.flags.mf",
            mf,
            r_ff.with_bitmask(0x2000),
            None,
        );
        ctx.add_u64(
            Some(root),
            "ip.frag_offset",
            frag_offset as u64,
            r_ff.with_bitmask(0x1fff),
            None,
        );
        ctx.add_u64(Some(root), "ip.ttl", ttl as u64, r_ttl, None);
        ctx.add_u64(
            Some(root),
            "ip.proto",
            proto as u64,
            r_proto,
            Some(format!("Protocol: {} ({proto})", ip_protocol_name(proto))),
        );

        let csum_node = ctx.add_u64(
            Some(root),
            "ip.checksum",
            csum as u64,
            r_csum,
            Some(format!("Header Checksum: 0x{csum:04x}")),
        );
        if raw_slice.len() >= ihl_bytes {
            let valid = verify_ipv4_checksum(&raw_slice[..ihl_bytes]);
            let status_str = if valid { "Good" } else { "Bad" };
            ctx.add_generated_str(
                Some(csum_node),
                "ip.checksum.status",
                status_str,
                r_csum,
                None,
            );
            // Note: checksum 0x0000 is often NIC TX offload; warn only on non-zero bad checksum
            if !valid && csum != 0 {
                ctx.add_expert(
                    csum_node,
                    ExpertSeverity::Warn,
                    ExpertGroup::Checksum,
                    format!("Header checksum 0x{csum:04x} is incorrect"),
                    r_csum,
                );
            }
        }

        ctx.add_ipv4(
            Some(root),
            "ip.src",
            src,
            r_src,
            Some(format!("Source Address: {src_disp}")),
        );
        ctx.add_ipv4(
            Some(root),
            "ip.dst",
            dst,
            r_dst,
            Some(format!("Destination Address: {dst_disp}")),
        );

        // Trim trailing Ethernet padding if total_len specifies a smaller IP payload
        let ip_payload_len = (total_len as usize).saturating_sub(ihl_bytes);
        if ip_payload_len < buf.remaining() {
            let mut trimmed = buf.sub_cursor(ip_payload_len)?;
            std::mem::swap(buf, &mut trimmed);
        }

        if frag_offset > 0 || mf {
            ctx.set_info(format!(
                "IPv4 Fragment (id=0x{ident:04x}, off={frag_offset}, mf={mf}) proto={}",
                ip_protocol_name(proto)
            ));
            if frag_offset > 0 {
                return Ok(Next::None);
            }
        } else {
            ctx.set_info(format!(
                "IPv4 {src_disp} -> {dst_disp} ({})",
                ip_protocol_name(proto)
            ));
        }

        Ok(Next::Table(TableId::IpProto, proto as u32))
    }
}

/// RFC 8200 Internet Protocol Version 6 dissector (`ipv6`).
pub struct Ipv6Dissector {
    proto_id: ProtocolId,
}

impl Ipv6Dissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Internet Protocol Version 6", "IPv6", "ipv6")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "ipv6.version", "Version", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ipv6.tclass", "Traffic Class", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ipv6.flow", "Flow Label", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "ipv6.plen", "Payload Length", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "ipv6.nxt", "Next Header", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ipv6.hlim", "Hop Limit", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ipv6.src", "Source Address", FieldType::Ipv6, "");
        let _ = reg.register_field(pid, "ipv6.dst", "Destination Address", FieldType::Ipv6, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for Ipv6Dissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (vcf, r_vcf) = buf.read_u32_be()?;
        let version = (vcf >> 28) as u8;
        let tclass = ((vcf >> 20) & 0xff) as u8;
        let flow = vcf & 0x000f_ffff;
        let (plen, r_plen) = buf.read_u16_be()?;
        let (mut nxt, r_nxt) = buf.read_u8()?;
        let (hlim, r_hlim) = buf.read_u8()?;
        let (src, r_src) = buf.read_ipv6()?;
        let (dst, r_dst) = buf.read_ipv6()?;

        let src_raw = Ipv6Addr::from(src).to_string();
        let dst_raw = Ipv6Addr::from(dst).to_string();
        let src_disp = ctx.resolver.format_ipv6(src);
        let dst_disp = ctx.resolver.format_ipv6(dst);

        ctx.net_src_raw = Some(src_raw);
        ctx.net_dst_raw = Some(dst_raw);
        ctx.summary.source = src_disp.clone();
        ctx.summary.destination = dst_disp.clone();

        let hdr_range = buf.range_from(start);
        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Internet Protocol Version 6, Src: {src_disp}, Dst: {dst_disp}"),
            hdr_range,
        );
        ctx.add_u64(Some(root), "ipv6.version", version as u64, r_vcf, None);
        ctx.add_u64(Some(root), "ipv6.tclass", tclass as u64, r_vcf, None);
        ctx.add_u64(Some(root), "ipv6.flow", flow as u64, r_vcf, None);
        ctx.add_u64(Some(root), "ipv6.plen", plen as u64, r_plen, None);
        ctx.add_u64(
            Some(root),
            "ipv6.nxt",
            nxt as u64,
            r_nxt,
            Some(format!("Next Header: {} ({nxt})", ip_protocol_name(nxt))),
        );
        ctx.add_u64(Some(root), "ipv6.hlim", hlim as u64, r_hlim, None);
        ctx.add_ipv6(Some(root), "ipv6.src", src, r_src, None);
        ctx.add_ipv6(Some(root), "ipv6.dst", dst, r_dst, None);

        // Walk standard IPv6 extension headers (Hop-by-Hop=0, Routing=43, Fragment=44, DestOpts=60)
        for _ in 0..8 {
            match nxt {
                0 | 43 | 60 => {
                    if buf.remaining() < 2 {
                        break;
                    }
                    let (ext_nxt, _) = buf.read_u8()?;
                    let (ext_len, _) = buf.read_u8()?;
                    let skip = ((ext_len as usize) + 1) * 8 - 2;
                    let _ = buf.read_bytes(skip)?;
                    nxt = ext_nxt;
                }
                44 => {
                    // IPv6 Fragment Header (8 bytes)
                    let (ext_nxt, _) = buf.read_u8()?;
                    let _ = buf.read_u8()?;
                    let (frag_off_m, _) = buf.read_u16_be()?;
                    let _ = buf.read_u32_be()?;
                    let frag_off = (frag_off_m >> 3) * 8;
                    nxt = ext_nxt;
                    if frag_off > 0 {
                        ctx.set_info(format!("IPv6 Fragment (offset={frag_off})"));
                        return Ok(Next::None);
                    }
                }
                _ => break,
            }
        }

        ctx.update_node_range(root, buf.range_from(start));
        ctx.set_info(format!(
            "IPv6 {src_disp} -> {dst_disp} ({})",
            ip_protocol_name(nxt)
        ));
        Ok(Next::Table(TableId::IpProto, nxt as u32))
    }
}

/// RFC 792 Internet Control Message Protocol dissector (`icmp`).
pub struct IcmpDissector {
    proto_id: ProtocolId,
}

impl IcmpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Internet Control Message Protocol", "ICMP", "icmp")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "icmp.type", "Type", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "icmp.code", "Code", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "icmp.checksum", "Checksum", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "icmp.ident", "Identifier", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "icmp.seq", "Sequence Number", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "icmp.resp_to",
            "Request Frame",
            FieldType::Uint64,
            "",
        );
        let _ = reg.register_field(
            pid,
            "icmp.resptime",
            "Response Time (ms)",
            FieldType::Float64,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for IcmpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (icmp_type, r_type) = buf.read_u8()?;
        let (code, r_code) = buf.read_u8()?;
        let (csum, r_csum) = buf.read_u16_be()?;

        let type_desc = match icmp_type {
            0 => "Echo (ping) reply",
            3 => "Destination unreachable",
            5 => "Redirect",
            8 => "Echo (ping) request",
            11 => "Time-to-live exceeded",
            _ => "ICMP message",
        };

        let root = ctx.begin_protocol(
            self.proto_id,
            "Internet Control Message Protocol",
            buf.remaining_range(),
        );
        ctx.add_u64(
            Some(root),
            "icmp.type",
            icmp_type as u64,
            r_type,
            Some(format!("Type: {icmp_type} ({type_desc})")),
        );
        ctx.add_u64(Some(root), "icmp.code", code as u64, r_code, None);
        ctx.add_u64(
            Some(root),
            "icmp.checksum",
            csum as u64,
            r_csum,
            Some(format!("Checksum: 0x{csum:04x}")),
        );

        if (icmp_type == 8 || icmp_type == 0) && buf.remaining() >= 4 {
            let (id, r_id) = buf.read_u16_be()?;
            let (seq, r_seq) = buf.read_u16_be()?;
            ctx.add_u64(Some(root), "icmp.ident", id as u64, r_id, None);
            ctx.add_u64(Some(root), "icmp.seq", seq as u64, r_seq, None);

            let src_ip = ctx.net_src_raw.clone().unwrap_or_default();
            let dst_ip = ctx.net_dst_raw.clone().unwrap_or_default();
            let mut extra = String::new();
            if icmp_type == 8 {
                ctx.conversations.record_icmp_echo_request(
                    &src_ip,
                    &dst_ip,
                    id,
                    seq,
                    ctx.frame.number,
                    ctx.frame.timestamp,
                );
            } else if let Some((req_frame, rtt_sec)) = ctx.conversations.match_icmp_echo_reply(
                &src_ip,
                &dst_ip,
                id,
                seq,
                ctx.frame.number,
                ctx.frame.timestamp,
            ) {
                let rtt_ms = rtt_sec * 1_000.0;
                let hdr_r = buf.range_from(start);
                ctx.add_generated_u64(Some(root), "icmp.resp_to", req_frame, hdr_r, None);
                ctx.add_generated_f64(Some(root), "icmp.resptime", rtt_ms, hdr_r, None);
                extra = format!(" (request in {req_frame}, rtt={rtt_ms:.3} ms)");
            }

            let _ = buf.read_bytes(buf.remaining())?;
            ctx.update_node_range(root, buf.range_from(start));
            ctx.set_info(format!(
                "{type_desc} id=0x{id:04x}, seq={seq}, ttl={}{extra}",
                ctx.tree
                    .by_abbrev("ip.ttl")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0)
            ));
        } else {
            let _ = buf.read_bytes(buf.remaining())?;
            ctx.update_node_range(root, buf.range_from(start));
            ctx.set_info(format!("{type_desc} (type={icmp_type}, code={code})"));
        }

        Ok(Next::None)
    }
}

/// RFC 4443 / RFC 4861 ICMPv6 and Neighbor Discovery dissector (`icmpv6`).
pub struct Icmpv6Dissector {
    proto_id: ProtocolId,
}

impl Icmpv6Dissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol(
                "Internet Control Message Protocol v6",
                "ICMPv6",
                "icmpv6",
            )
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "icmpv6.type", "Type", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "icmpv6.code", "Code", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "icmpv6.checksum", "Checksum", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "icmpv6.nd.target",
            "Target Address",
            FieldType::Ipv6,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for Icmpv6Dissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (t, r_t) = buf.read_u8()?;
        let (code, r_c) = buf.read_u8()?;
        let (csum, r_csum) = buf.read_u16_be()?;

        let desc = match t {
            1 => "Destination Unreachable",
            2 => "Packet Too Big",
            3 => "Time Exceeded",
            128 => "Echo (ping) request",
            129 => "Echo (ping) reply",
            133 => "Router Solicitation",
            134 => "Router Advertisement",
            135 => "Neighbor Solicitation",
            136 => "Neighbor Advertisement",
            _ => "ICMPv6 Message",
        };

        let root = ctx.begin_protocol(
            self.proto_id,
            "Internet Control Message Protocol v6",
            buf.range_from(start),
        );
        ctx.add_u64(
            Some(root),
            "icmpv6.type",
            t as u64,
            r_t,
            Some(format!("Type: {desc} ({t})")),
        );
        ctx.add_u64(Some(root), "icmpv6.code", code as u64, r_c, None);
        ctx.add_u64(Some(root), "icmpv6.checksum", csum as u64, r_csum, None);

        if (t == 135 || t == 136) && buf.remaining() >= 20 {
            let _ = buf.read_u32_be()?;
            let (target, r_target) = buf.read_ipv6()?;
            let target_str = Ipv6Addr::from(target).to_string();
            ctx.add_ipv6(Some(root), "icmpv6.nd.target", target, r_target, None);
            let _ = buf.read_bytes(buf.remaining())?;
            ctx.update_node_range(root, buf.range_from(start));
            ctx.set_info(format!("{desc} for {target_str}"));
        } else {
            let _ = buf.read_bytes(buf.remaining())?;
            ctx.update_node_range(root, buf.range_from(start));
            ctx.set_info(desc.to_string());
        }

        Ok(Next::None)
    }
}

/// RFC 2236 / RFC 3376 Internet Group Management Protocol (`igmp`).
pub struct IgmpDissector {
    proto_id: ProtocolId,
}

impl IgmpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Internet Group Management Protocol", "IGMP", "igmp")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "igmp.type", "Type", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "igmp.max_resp", "Max Resp Time", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "igmp.checksum", "Checksum", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "igmp.maddr", "Multicast Address", FieldType::Ipv4, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for IgmpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (igmp_type, r_type) = buf.read_u8()?;
        let (max_resp, r_resp) = buf.read_u8()?;
        let (csum, r_csum) = buf.read_u16_be()?;
        let (maddr, r_maddr) = buf.read_ipv4()?;
        let _ = buf.read_bytes(buf.remaining())?;
        let hdr_range = buf.range_from(start);

        let root = ctx.begin_protocol(
            self.proto_id,
            "Internet Group Management Protocol",
            hdr_range,
        );
        ctx.add_u64(Some(root), "igmp.type", igmp_type as u64, r_type, None);
        ctx.add_u64(Some(root), "igmp.max_resp", max_resp as u64, r_resp, None);
        ctx.add_u64(Some(root), "igmp.checksum", csum as u64, r_csum, None);
        ctx.add_ipv4(Some(root), "igmp.maddr", maddr, r_maddr, None);
        ctx.set_info(format!(
            "IGMP type=0x{igmp_type:02x} group {}",
            Ipv4Addr::from(maddr)
        ));
        Ok(Next::None)
    }
}

/// RFC 2784 / RFC 2890 Generic Routing Encapsulation (`gre`).
pub struct GreDissector {
    proto_id: ProtocolId,
}

impl GreDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Generic Routing Encapsulation", "GRE", "gre")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "gre.flags", "Flags and Version", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "gre.proto", "Protocol Type", FieldType::Uint16, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for GreDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (flags, r_flags) = buf.read_u16_be()?;
        let (proto, r_proto) = buf.read_u16_be()?;
        if (flags & 0x8000) != 0 {
            let _ = buf.read_u32_be()?; // checksum + reserved1
        }
        if (flags & 0x2000) != 0 {
            let _ = buf.read_u32_be()?; // key
        }
        if (flags & 0x1000) != 0 {
            let _ = buf.read_u32_be()?; // sequence number
        }
        let hdr_range = buf.range_from(start);
        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Generic Routing Encapsulation (0x{proto:04x})"),
            hdr_range,
        );
        ctx.add_u64(Some(root), "gre.flags", flags as u64, r_flags, None);
        ctx.add_u64(Some(root), "gre.proto", proto as u64, r_proto, None);
        Ok(Next::Table(TableId::EtherType, proto as u32))
    }
}

/// RFC 3032 Multi-Protocol Label Switching (`mpls`).
pub struct MplsDissector {
    proto_id: ProtocolId,
}

impl MplsDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol(
                "MultiProtocol Label Switching Header",
                "MPLS",
                "mpls",
            )
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "mpls.label", "MPLS Label", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "mpls.exp", "MPLS Experimental Bits", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "mpls.bottom",
            "MPLS Bottom Of Label Stack",
            FieldType::Bool,
            "",
        );
        let _ = reg.register_field(pid, "mpls.ttl", "MPLS TTL", FieldType::Uint8, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for MplsDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        loop {
            let (entry, r_entry) = buf.read_u32_be()?;
            let label = entry >> 12;
            let exp = ((entry >> 9) & 0x07) as u8;
            let bos = ((entry >> 8) & 0x01) != 0;
            let ttl = (entry & 0xff) as u8;

            let root = ctx.begin_protocol(
                self.proto_id,
                format!("MultiProtocol Label Switching Header, Label: {label}, Exp: {exp}, S: {}, TTL: {ttl}", u8::from(bos)),
                r_entry,
            );
            ctx.add_u64(Some(root), "mpls.label", label as u64, r_entry, None);
            ctx.add_u64(Some(root), "mpls.exp", exp as u64, r_entry, None);
            ctx.add_bool(Some(root), "mpls.bottom", bos, r_entry, None);
            ctx.add_u64(Some(root), "mpls.ttl", ttl as u64, r_entry, None);

            if bos {
                break;
            }
        }
        if let Ok(first_nibble) = buf.peek_u8() {
            match first_nibble >> 4 {
                4 => return Ok(Next::Table(TableId::EtherType, 0x0800)),
                6 => return Ok(Next::Table(TableId::EtherType, 0x86dd)),
                _ => {}
            }
        }
        Ok(Next::None)
    }
}
