use mash_core::{
    ByteRange, ExpertGroup, ExpertSeverity, FieldType, ProtocolId,
};
use mash_dissect::{
    DissectCtx, DissectResult, Dissector, Next, PacketCursor, Registry,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum DNS compression pointer jumps per name (REL-03 loop protection).
pub const MAX_DNS_JUMPS: usize = 32;

/// RFC 1035 / RFC 3596 Domain Name System dissector (`dns`).
pub struct DnsDissector {
    proto_id: ProtocolId,
}

impl DnsDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Domain Name System", "DNS", "dns")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "dns.id", "Transaction ID", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "dns.flags", "Flags", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "dns.flags.response", "Response", FieldType::Bool, "");
        let _ = reg.register_field(pid, "dns.flags.opcode", "Opcode", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "dns.flags.rcode", "Reply code", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "dns.count.queries", "Questions", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "dns.count.answers",
            "Answer RRs",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "dns.count.auth_rr",
            "Authority RRs",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "dns.count.add_rr",
            "Additional RRs",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "dns.qry.name", "Query Name", FieldType::String, "");
        let _ = reg.register_field(pid, "dns.qry.type", "Query Type", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "dns.qry.class", "Query Class", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "dns.resp.name", "Answer Name", FieldType::String, "");
        let _ = reg.register_field(pid, "dns.resp.type", "Answer Type", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "dns.resp.ttl", "Time to live", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "dns.a", "A (IPv4 Address)", FieldType::Ipv4, "");
        let _ = reg.register_field(pid, "dns.aaaa", "AAAA (IPv6 Address)", FieldType::Ipv6, "");
        let _ = reg.register_field(pid, "dns.cname", "CNAME", FieldType::String, "");
        let _ = reg.register_field(pid, "dns.ns", "NS", FieldType::String, "");
        let _ = reg.register_field(pid, "dns.ptr", "PTR", FieldType::String, "");
        let _ = reg.register_field(pid, "dns.txt", "TXT", FieldType::String, "");
        let _ = reg.register_field(pid, "dns.time", "Response Time (s)", FieldType::Float64, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

pub fn dns_qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        65 => "HTTPS",
        255 => "ANY",
        _ => "TYPE",
    }
}

pub fn dns_rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "No such name (NXDOMAIN)",
        4 => "Not implemented",
        5 => "Refused",
        _ => "Error",
    }
}

/// Decode an RFC 1035 domain name starting at `offset` within `msg`, enforcing `MAX_DNS_JUMPS` to prevent compression pointer loops (`REL-03`).
/// Returns `(decoded_name, next_offset_after_initial_name)`.
pub fn decode_dns_name(msg: &[u8], start_offset: usize) -> Result<(String, usize), &'static str> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start_offset;
    let mut jumped = false;
    let mut end_pos = start_offset;
    let mut jumps = 0usize;

    loop {
        if pos >= msg.len() {
            return Err("DNS name truncated");
        }
        let len_byte = msg[pos];
        if len_byte == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        if (len_byte & 0xc0) == 0xc0 {
            // Compression pointer
            if pos + 1 >= msg.len() {
                return Err("DNS compression pointer truncated");
            }
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > MAX_DNS_JUMPS {
                return Err("DNS compression pointer loop detected");
            }
            let ptr = (((len_byte & 0x3f) as usize) << 8) | (msg[pos + 1] as usize);
            if ptr >= msg.len() || ptr == pos {
                return Err("DNS compression pointer out of bounds");
            }
            pos = ptr;
        } else if (len_byte & 0xc0) == 0 {
            let label_len = len_byte as usize;
            pos += 1;
            if pos + label_len > msg.len() {
                return Err("DNS label exceeds message length");
            }
            let label = String::from_utf8_lossy(&msg[pos..pos + label_len]).to_string();
            labels.push(label);
            pos += label_len;
            if !jumped {
                end_pos = pos;
            }
            if labels.len() > 128 {
                return Err("DNS name exceeds maximum label count");
            }
        } else {
            return Err("Invalid DNS label compression bits");
        }
    }

    let name = if labels.is_empty() {
        "<Root>".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, end_pos))
}

impl Dissector for DnsDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        // If DNS is carried over TCP, there is a 2-byte length prefix before the DNS header
        if ctx.tree.has_field_or_protocol("tcp") && buf.remaining() >= 14 {
            let maybe_len = u16::from_be_bytes([buf.slice_remaining()[0], buf.slice_remaining()[1]]) as usize;
            if maybe_len + 2 == buf.remaining() {
                let _ = buf.read_u16_be()?;
            }
        }

        let dns_base_abs = buf.abs_offset();
        let msg = buf.slice_remaining();
        let (txid, r_id) = buf.read_u16_be()?;
        let (flags, r_flags) = buf.read_u16_be()?;
        let (qdcount, r_qd) = buf.read_u16_be()?;
        let (ancount, r_an) = buf.read_u16_be()?;
        let (nscount, r_ns) = buf.read_u16_be()?;
        let (arcount, r_ar) = buf.read_u16_be()?;

        let is_response = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0f) as u8;
        let rcode = (flags & 0x0f) as u8;

        let full_range = ByteRange::with_source(buf.source_idx(), dns_base_abs, dns_base_abs + msg.len());
        let root = ctx.begin_protocol(
            self.proto_id,
            format!(
                "Domain Name System ({})",
                if is_response { "response" } else { "query" }
            ),
            full_range,
        );

        ctx.add_u64(
            Some(root),
            "dns.id",
            txid as u64,
            r_id,
            Some(format!("Transaction ID: 0x{txid:04x}")),
        );
        let flags_node = ctx.add_u64(
            Some(root),
            "dns.flags",
            flags as u64,
            r_flags,
            Some(format!("Flags: 0x{flags:04x}")),
        );
        ctx.add_bool(Some(flags_node), "dns.flags.response", is_response, r_flags, None);
        ctx.add_u64(Some(flags_node), "dns.flags.opcode", opcode as u64, r_flags, None);
        ctx.add_u64(
            Some(flags_node),
            "dns.flags.rcode",
            rcode as u64,
            r_flags,
            Some(format!("Reply code: {} ({rcode})", dns_rcode_name(rcode))),
        );
        if is_response && rcode != 0 {
            ctx.add_expert(
                flags_node,
                ExpertSeverity::Note,
                ExpertGroup::ResponseCode,
                format!("DNS response error: {} (rcode={rcode})", dns_rcode_name(rcode)),
                r_flags,
            );
        }

        ctx.add_u64(Some(root), "dns.count.queries", qdcount as u64, r_qd, None);
        ctx.add_u64(Some(root), "dns.count.answers", ancount as u64, r_an, None);
        ctx.add_u64(Some(root), "dns.count.auth_rr", nscount as u64, r_ns, None);
        ctx.add_u64(Some(root), "dns.count.add_rr", arcount as u64, r_ar, None);

        let mut offset = 12usize;
        let mut query_summaries = Vec::new();
        let mut answer_summaries = Vec::new();

        // Parse Questions (cap at 64 to guard against malformed counts)
        for _ in 0..qdcount.min(64) {
            if offset >= msg.len() {
                break;
            }
            match decode_dns_name(msg, offset) {
                Ok((qname, next_off)) => {
                    if next_off + 4 > msg.len() {
                        ctx.add_expert(
                            root,
                            ExpertSeverity::Error,
                            ExpertGroup::Malformed,
                            "DNS question truncated".to_string(),
                            full_range,
                        );
                        break;
                    }
                    let qtype = u16::from_be_bytes([msg[next_off], msg[next_off + 1]]);
                    let qclass = u16::from_be_bytes([msg[next_off + 2], msg[next_off + 3]]);
                    let q_range = ByteRange::with_source(
                        buf.source_idx(),
                        dns_base_abs + offset,
                        dns_base_abs + next_off + 4,
                    );
                    ctx.add_str(Some(root), "dns.qry.name", qname.clone(), q_range, None);
                    ctx.add_u64(
                        Some(root),
                        "dns.qry.type",
                        qtype as u64,
                        q_range,
                        Some(format!("Type: {} ({qtype})", dns_qtype_name(qtype))),
                    );
                    ctx.add_u64(Some(root), "dns.qry.class", qclass as u64, q_range, None);
                    query_summaries.push(format!("{} {}", dns_qtype_name(qtype), qname));
                    offset = next_off + 4;
                }
                Err(err_msg) => {
                    ctx.add_expert(
                        root,
                        ExpertSeverity::Error,
                        ExpertGroup::Malformed,
                        err_msg.to_string(),
                        full_range,
                    );
                    ctx.append_info(" [Malformed DNS Name]");
                    return Ok(Next::None);
                }
            }
        }

        // Parse Resource Records (Answers + Authority + Additional)
        let total_rrs = (ancount as usize)
            .saturating_add(nscount as usize)
            .saturating_add(arcount as usize)
            .min(128);
        for rr_idx in 0..total_rrs {
            if offset >= msg.len() {
                break;
            }
            let Ok((rr_name, next_off)) = decode_dns_name(msg, offset) else {
                ctx.add_expert(
                    root,
                    ExpertSeverity::Error,
                    ExpertGroup::Malformed,
                    "Malformed DNS resource record name".to_string(),
                    full_range,
                );
                break;
            };
            if next_off + 10 > msg.len() {
                break;
            }
            let rtype = u16::from_be_bytes([msg[next_off], msg[next_off + 1]]);
            let ttl = u32::from_be_bytes([
                msg[next_off + 4],
                msg[next_off + 5],
                msg[next_off + 6],
                msg[next_off + 7],
            ]);
            let rdlen = u16::from_be_bytes([msg[next_off + 8], msg[next_off + 9]]) as usize;
            let rdata_start = next_off + 10;
            let rdata_end = rdata_start.saturating_add(rdlen);
            if rdata_end > msg.len() {
                ctx.add_expert(
                    root,
                    ExpertSeverity::Error,
                    ExpertGroup::Malformed,
                    "DNS resource record RDATA exceeds packet".to_string(),
                    full_range,
                );
                break;
            }

            let rr_range = ByteRange::with_source(
                buf.source_idx(),
                dns_base_abs + offset,
                dns_base_abs + rdata_end,
            );
            let rdata_range = ByteRange::with_source(
                buf.source_idx(),
                dns_base_abs + rdata_start,
                dns_base_abs + rdata_end,
            );
            ctx.add_str(Some(root), "dns.resp.name", rr_name.clone(), rr_range, None);
            ctx.add_u64(
                Some(root),
                "dns.resp.type",
                rtype as u64,
                rr_range,
                Some(format!("Type: {} ({rtype})", dns_qtype_name(rtype))),
            );
            ctx.add_u64(Some(root), "dns.resp.ttl", ttl as u64, rr_range, None);

            let rdata = &msg[rdata_start..rdata_end];
            match rtype {
                1 if rdata.len() == 4 => {
                    let ip = [rdata[0], rdata[1], rdata[2], rdata[3]];
                    ctx.add_ipv4(Some(root), "dns.a", ip, rdata_range, None);
                    ctx.resolver.learn_dns_v4(ip, rr_name.clone());
                    if rr_idx < (ancount as usize) {
                        answer_summaries.push(format!("A {}", Ipv4Addr::from(ip)));
                    }
                }
                28 if rdata.len() == 16 => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(rdata);
                    ctx.add_ipv6(Some(root), "dns.aaaa", ip, rdata_range, None);
                    ctx.resolver.learn_dns_v6(ip, rr_name.clone());
                    if rr_idx < (ancount as usize) {
                        answer_summaries.push(format!("AAAA {}", Ipv6Addr::from(ip)));
                    }
                }
                5 | 2 | 12 => {
                    if let Ok((target_name, _)) = decode_dns_name(msg, rdata_start) {
                        let abbrev = match rtype {
                            5 => "dns.cname",
                            2 => "dns.ns",
                            _ => "dns.ptr",
                        };
                        ctx.add_str(
                            Some(root),
                            abbrev,
                            target_name.clone(),
                            rdata_range,
                            None,
                        );
                        if rr_idx < (ancount as usize) {
                            answer_summaries
                                .push(format!("{} {}", dns_qtype_name(rtype), target_name));
                        }
                    }
                }
                16 if !rdata.is_empty() => {
                    let txt_len = (rdata[0] as usize).min(rdata.len().saturating_sub(1));
                    let txt = String::from_utf8_lossy(&rdata[1..1 + txt_len]).to_string();
                    ctx.add_str(Some(root), "dns.txt", txt.clone(), rdata_range, None);
                    if rr_idx < (ancount as usize) {
                        answer_summaries.push(format!("TXT \"{txt}\""));
                    }
                }
                _ => {}
            }

            offset = rdata_end;
        }

        let stream_id = ctx.stream_id.unwrap_or(0);
        let q_joined = query_summaries.join(", ");
        if !is_response {
            ctx.conversations.record_dns_query(
                stream_id,
                txid,
                ctx.frame.number,
                ctx.frame.timestamp,
                q_joined.clone(),
            );
            ctx.set_info(format!("Standard query 0x{txid:04x} {q_joined}"));
        } else {
            if let Some((_, rtt)) = ctx.conversations.match_dns_response(
                stream_id,
                txid,
                ctx.frame.number,
                ctx.frame.timestamp,
            ) {
                ctx.add_generated_f64(Some(root), "dns.time", rtt, full_range, None);
            }
            let ans_tail = if answer_summaries.is_empty() {
                if rcode != 0 {
                    format!(" {}", dns_rcode_name(rcode))
                } else {
                    String::new()
                }
            } else {
                format!(" {}", answer_summaries.join(", "))
            };
            ctx.set_info(format!(
                "Standard query response 0x{txid:04x} {q_joined}{ans_tail}"
            ));
        }

        let _ = buf.read_bytes(buf.remaining())?;
        Ok(Next::None)
    }
}

/// RFC 2131 / RFC 2132 Dynamic Host Configuration Protocol dissector (`dhcp`).
pub struct DhcpDissector {
    proto_id: ProtocolId,
}

impl DhcpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol(
                "Dynamic Host Configuration Protocol",
                "DHCP",
                "dhcp",
            )
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "dhcp.op", "Message type", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "dhcp.id", "Transaction ID", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "dhcp.ip.client", "Client IP address", FieldType::Ipv4, "");
        let _ = reg.register_field(
            pid,
            "dhcp.ip.your",
            "Your (client) IP address",
            FieldType::Ipv4,
            "",
        );
        let _ = reg.register_field(
            pid,
            "dhcp.ip.server",
            "Next server IP address",
            FieldType::Ipv4,
            "",
        );
        let _ = reg.register_field(
            pid,
            "dhcp.hw.mac_addr",
            "Client MAC address",
            FieldType::MacAddr,
            "",
        );
        let _ = reg.register_field(
            pid,
            "dhcp.option.dhcp",
            "DHCP Message Type",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(
            pid,
            "dhcp.option.hostname",
            "Host Name",
            FieldType::String,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for DhcpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (op, r_op) = buf.read_u8()?;
        let _ = buf.read_u8()?; // htype
        let _ = buf.read_u8()?; // hlen
        let _ = buf.read_u8()?; // hops
        let (xid, r_xid) = buf.read_u32_be()?;
        let _ = buf.read_u16_be()?; // secs
        let _ = buf.read_u16_be()?; // flags
        let (ciaddr, r_ci) = buf.read_ipv4()?;
        let (yiaddr, r_yi) = buf.read_ipv4()?;
        let (siaddr, r_si) = buf.read_ipv4()?;
        let _ = buf.read_ipv4()?; // giaddr
        let (chaddr, r_mac) = buf.read_mac()?;
        let _ = buf.read_bytes(10 + 64 + 128)?; // chaddr pad (10) + sname (64) + file (128)
        let (cookie, _) = buf.read_u32_be()?;

        let root = ctx.begin_protocol(
            self.proto_id,
            "Dynamic Host Configuration Protocol",
            buf.remaining_range(),
        );
        ctx.add_u64(Some(root), "dhcp.op", op as u64, r_op, None);
        ctx.add_u64(
            Some(root),
            "dhcp.id",
            xid as u64,
            r_xid,
            Some(format!("Transaction ID: 0x{xid:08x}")),
        );
        ctx.add_ipv4(Some(root), "dhcp.ip.client", ciaddr, r_ci, None);
        ctx.add_ipv4(Some(root), "dhcp.ip.your", yiaddr, r_yi, None);
        ctx.add_ipv4(Some(root), "dhcp.ip.server", siaddr, r_si, None);
        ctx.add_mac(Some(root), "dhcp.hw.mac_addr", chaddr, r_mac, None);

        let mut msg_type_str = if op == 1 { "Boot Request" } else { "Boot Reply" };
        if cookie == 0x6382_5363 {
            while buf.remaining() > 0 {
                let (opt_code, r_opt) = buf.read_u8()?;
                if opt_code == 255 {
                    break;
                }
                if opt_code == 0 {
                    continue;
                }
                if buf.remaining() == 0 {
                    break;
                }
                let (opt_len, _) = buf.read_u8()?;
                let (val, r_val) = buf.read_bytes(opt_len as usize)?;
                match opt_code {
                    53 if !val.is_empty() => {
                        let mt = val[0];
                        msg_type_str = match mt {
                            1 => "DHCP Discover",
                            2 => "DHCP Offer",
                            3 => "DHCP Request",
                            4 => "DHCP Decline",
                            5 => "DHCP ACK",
                            6 => "DHCP NAK",
                            7 => "DHCP Release",
                            8 => "DHCP Inform",
                            _ => "DHCP Message",
                        };
                        ctx.add_u64(
                            Some(root),
                            "dhcp.option.dhcp",
                            mt as u64,
                            r_opt,
                            Some(format!("DHCP Message Type: {msg_type_str} ({mt})")),
                        );
                    }
                    12 => {
                        let hn = String::from_utf8_lossy(val).to_string();
                        ctx.add_str(Some(root), "dhcp.option.hostname", hn, r_val, None);
                    }
                    _ => {}
                }
            }
        }
        let _ = buf.read_bytes(buf.remaining())?;
        ctx.update_node_range(root, buf.range_from(start));
        ctx.set_info(format!("{msg_type_str} - Transaction ID 0x{xid:08x}"));
        Ok(Next::None)
    }
}

/// RFC 9110 / RFC 9112 Hypertext Transfer Protocol 1.x dissector (`http`).
pub struct HttpDissector {
    proto_id: ProtocolId,
}

impl HttpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Hypertext Transfer Protocol", "HTTP", "http")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "http.request.method",
            "Request Method",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.request.uri",
            "Request URI",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.request.version",
            "Request Version",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.response.version",
            "Response Version",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.response.code",
            "Status Code",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.response.phrase",
            "Response Phrase",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(pid, "http.host", "Host", FieldType::String, "");
        let _ = reg.register_field(pid, "http.user_agent", "User-Agent", FieldType::String, "");
        let _ = reg.register_field(
            pid,
            "http.content_type",
            "Content-Type",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.content_length",
            "Content-Length",
            FieldType::Uint64,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.content_encoding",
            "Content-Encoding",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(
            pid,
            "http.authorization",
            "Authorization",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(pid, "http.cookie", "Cookie", FieldType::String, "");
        let _ = reg.register_field(pid, "http.server", "Server", FieldType::String, "");
        let _ = reg.register_field(pid, "http.file_data", "File Data", FieldType::Bytes, "");
        let _ = reg.register_field(pid, "http.time", "Time since request", FieldType::Float64, "");
        let _ = reg.register_field(
            pid,
            "http.request_in",
            "Request in frame",
            FieldType::Uint64,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn is_http_prefix(buf: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"HTTP/1.",
    ];
    PREFIXES.iter().any(|p| buf.starts_with(p))
}

impl Dissector for HttpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn heuristic_probe(&self, buf: &[u8], _ctx: &DissectCtx<'_>) -> bool {
        is_http_prefix(buf)
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let raw = buf.slice_remaining();
        if !is_http_prefix(raw) {
            return Ok(Next::None);
        }

        let ( all_bytes, full_range) = buf.read_bytes(raw.len())?;
        let text = String::from_utf8_lossy(all_bytes);
        let (headers_part, body_offset) = if let Some(idx) = text.find("\r\n\r\n") {
            (&text[..idx], Some(idx + 4))
        } else if let Some(idx) = text.find("\n\n") {
            (&text[..idx], Some(idx + 2))
        } else {
            (text.as_ref(), None)
        };

        let mut lines = headers_part.lines();
        let Some(first_line) = lines.next() else {
            return Ok(Next::None);
        };
        let first_line_trimmed = first_line.trim();
        let first_line_range = ByteRange::with_source(
            buf.source_idx(),
            start,
            start + first_line.len().min(all_bytes.len()),
        );

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Hypertext Transfer Protocol ({first_line_trimmed})"),
            full_range,
        );

        let stream_id = ctx.stream_id.unwrap_or(0);
        if first_line_trimmed.starts_with("HTTP/") {
            let mut parts = first_line_trimmed.splitn(3, ' ');
            let ver = parts.next().unwrap_or("");
            let code_str = parts.next().unwrap_or("0");
            let phrase = parts.next().unwrap_or("");
            let code = code_str.parse::<u16>().unwrap_or(0);

            ctx.add_str(
                Some(root),
                "http.response.version",
                ver,
                first_line_range,
                None,
            );
            let code_node = ctx.add_u64(
                Some(root),
                "http.response.code",
                code as u64,
                first_line_range,
                None,
            );
            ctx.add_str(
                Some(root),
                "http.response.phrase",
                phrase,
                first_line_range,
                None,
            );

            if code >= 400 {
                let sev = if code >= 500 {
                    ExpertSeverity::Warn
                } else {
                    ExpertSeverity::Note
                };
                ctx.add_expert(
                    code_node,
                    sev,
                    ExpertGroup::ResponseCode,
                    format!("HTTP {code} {phrase}"),
                    first_line_range,
                );
            }

            if let Some((req_frame, rtt, _uri)) = ctx.conversations.match_http_response(
                stream_id,
                ctx.frame.number,
                ctx.frame.timestamp,
            ) {
                ctx.add_generated_u64(Some(root), "http.request_in", req_frame, full_range, None);
                ctx.add_generated_f64(Some(root), "http.time", rtt, full_range, None);
            }
        } else {
            let mut parts = first_line_trimmed.splitn(3, ' ');
            let method = parts.next().unwrap_or("");
            let uri = parts.next().unwrap_or("");
            let ver = parts.next().unwrap_or("");
            ctx.add_str(
                Some(root),
                "http.request.method",
                method,
                first_line_range,
                None,
            );
            ctx.add_str(Some(root), "http.request.uri", uri, first_line_range, None);
            ctx.add_str(
                Some(root),
                "http.request.version",
                ver,
                first_line_range,
                None,
            );
            ctx.conversations.record_http_request(
                stream_id,
                ctx.frame.number,
                ctx.frame.timestamp,
                uri.to_string(),
            );
        }

        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key_lower = k.trim().to_ascii_lowercase();
                let val = v.trim();
                match key_lower.as_str() {
                    "host" => {
                        ctx.add_str(Some(root), "http.host", val, full_range, None);
                    }
                    "user-agent" => {
                        ctx.add_str(Some(root), "http.user_agent", val, full_range, None);
                    }
                    "content-type" => {
                        ctx.add_str(Some(root), "http.content_type", val, full_range, None);
                    }
                    "content-length" => {
                        if let Ok(cl) = val.parse::<u64>() {
                            ctx.add_u64(Some(root), "http.content_length", cl, full_range, None);
                        }
                    }
                    "content-encoding" => {
                        ctx.add_str(Some(root), "http.content_encoding", val, full_range, None);
                    }
                    "authorization" => {
                        ctx.add_str(Some(root), "http.authorization", val, full_range, None);
                    }
                    "cookie" => {
                        ctx.add_str(Some(root), "http.cookie", val, full_range, None);
                    }
                    "server" => {
                        ctx.add_str(Some(root), "http.server", val, full_range, None);
                    }
                    _ => {}
                }
            }
        }

        if let Some(b_off) = body_offset {
            if b_off < all_bytes.len() {
                let body_bytes = all_bytes[b_off..].to_vec();
                let body_range = ByteRange::with_source(
                    buf.source_idx(),
                    start + b_off,
                    start + all_bytes.len(),
                );
                ctx.add_bytes(Some(root), "http.file_data", body_bytes, body_range, None);
            }
        }

        ctx.set_info(first_line_trimmed.to_string());
        Ok(Next::None)
    }
}

/// RFC 5246 / RFC 8446 Transport Layer Security dissector (`tls`).
pub struct TlsDissector {
    proto_id: ProtocolId,
}

impl TlsDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Transport Layer Security", "TLS", "tls")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "tls.record.content_type",
            "Content Type",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tls.record.version",
            "Version",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "tls.record.length", "Length", FieldType::Uint16, "");
        let _ = reg.register_field(
            pid,
            "tls.handshake.type",
            "Handshake Type",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tls.handshake.version",
            "Handshake Version",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tls.handshake.random",
            "Random",
            FieldType::Bytes,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tls.handshake.ciphersuite",
            "Cipher Suite",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tls.handshake.extensions_server_name",
            "Server Name (SNI)",
            FieldType::String,
            "",
        );
        let _ = reg.register_field(
            pid,
            "tls.handshake.extensions_alpn_str",
            "ALPN Protocol",
            FieldType::String,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn looks_like_tls_record(buf: &[u8]) -> bool {
    if buf.len() < 5 {
        return false;
    }
    let content_type = buf[0];
    let ver_major = buf[1];
    let ver_minor = buf[2];
    matches!(content_type, 20..=23) && ver_major == 0x03 && ver_minor <= 0x04
}

impl Dissector for TlsDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn heuristic_probe(&self, buf: &[u8], _ctx: &DissectCtx<'_>) -> bool {
        looks_like_tls_record(buf)
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        if !looks_like_tls_record(buf.slice_remaining()) {
            return Ok(Next::None);
        }

        let start = buf.abs_offset();
        let root = ctx.begin_protocol(
            self.proto_id,
            "Transport Layer Security",
            buf.remaining_range(),
        );

        let mut info_parts = Vec::new();
        while buf.remaining() >= 5 {
            if !looks_like_tls_record(buf.slice_remaining()) {
                break;
            }
            let (ct, r_ct) = buf.read_u8()?;
            let (ver, r_ver) = buf.read_u16_be()?;
            let (rec_len, r_len) = buf.read_u16_be()?;

            ctx.add_u64(Some(root), "tls.record.content_type", ct as u64, r_ct, None);
            ctx.add_u64(
                Some(root),
                "tls.record.version",
                ver as u64,
                r_ver,
                Some(format!("Version: 0x{ver:04x}")),
            );
            ctx.add_u64(Some(root), "tls.record.length", rec_len as u64, r_len, None);

            if (rec_len as usize) > buf.remaining() {
                let _ = buf.read_bytes(buf.remaining())?;
                return Ok(Next::NeedMore {
                    needed: Some(rec_len as usize),
                });
            }

            let (rec_body, r_body) = buf.read_bytes(rec_len as usize)?;
            match ct {
                20 => info_parts.push("Change Cipher Spec".to_string()),
                21 => info_parts.push("Encrypted Alert".to_string()),
                22 => {
                    // Handshake record
                    if rec_body.len() >= 4 {
                        let hs_type = rec_body[0];
                        let hs_len =
                            u32::from_be_bytes([0, rec_body[1], rec_body[2], rec_body[3]]) as usize;
                        ctx.add_u64(
                            Some(root),
                            "tls.handshake.type",
                            hs_type as u64,
                            r_body,
                            None,
                        );
                        let hs_name = match hs_type {
                            1 => "Client Hello",
                            2 => "Server Hello",
                            11 => "Certificate",
                            12 => "Server Key Exchange",
                            14 => "Server Hello Done",
                            16 => "Client Key Exchange",
                            20 => "Finished",
                            _ => "Handshake",
                        };
                        let mut hs_label = hs_name.to_string();
                        if (hs_type == 1 || hs_type == 2) && rec_body.len() >= 4 + 34 && hs_len + 4 <= rec_body.len() {
                            let hs_payload = &rec_body[4..4 + hs_len];
                            if let Some(sni) = parse_tls_hello(ctx, root, hs_type, hs_payload, r_body) {
                                hs_label = format!("{hs_name} (SNI={sni})");
                            }
                        }
                        info_parts.push(hs_label);
                    } else {
                        info_parts.push("Encrypted Handshake Message".to_string());
                    }
                }
                23 => info_parts.push("Application Data".to_string()),
                _ => {}
            }
        }

        let _ = buf.read_bytes(buf.remaining())?;
        ctx.update_node_range(root, buf.range_from(start));
        if !info_parts.is_empty() {
            ctx.set_info(info_parts.join(", "));
        }
        Ok(Next::None)
    }
}

fn parse_tls_hello(
    ctx: &mut DissectCtx<'_>,
    root: mash_core::NodeId,
    hs_type: u8,
    hs: &[u8],
    range: ByteRange,
) -> Option<String> {
    if hs.len() < 35 {
        return None;
    }
    let client_ver = u16::from_be_bytes([hs[0], hs[1]]);
    let random = hs[2..34].to_vec();
    ctx.add_u64(
        Some(root),
        "tls.handshake.version",
        client_ver as u64,
        range,
        None,
    );
    ctx.add_bytes(Some(root), "tls.handshake.random", random, range, None);

    let mut pos = 34usize;
    let sid_len = hs[pos] as usize;
    pos += 1 + sid_len;
    if pos >= hs.len() {
        return None;
    }

    if hs_type == 1 {
        // ClientHello: cipher_suites_len (2) + cipher_suites + comp_methods_len (1) + comp_methods
        if pos + 2 > hs.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
        pos += 2;
        if pos + cs_len > hs.len() {
            return None;
        }
        for &chunk in hs[pos..pos + cs_len].as_chunks::<2>().0 {
            let cs = u16::from_be_bytes(chunk);
            ctx.add_u64(
                Some(root),
                "tls.handshake.ciphersuite",
                cs as u64,
                range,
                None,
            );
        }
        pos += cs_len;
        if pos >= hs.len() {
            return None;
        }
        let comp_len = hs[pos] as usize;
        pos += 1 + comp_len;
    } else {
        // ServerHello: cipher_suite (2) + comp_method (1)
        if pos + 3 > hs.len() {
            return None;
        }
        let cs = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        ctx.add_u64(
            Some(root),
            "tls.handshake.ciphersuite",
            cs as u64,
            range,
            None,
        );
        pos += 3;
    }

    // Extensions
    if pos + 2 > hs.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(hs.len());
    let mut found_sni = None;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        let ext_val = &hs[pos..pos + ext_len];
        match ext_type {
            // server_name (SNI)
            0x0000 if ext_val.len() >= 5 => {
                let name_len = u16::from_be_bytes([ext_val[3], ext_val[4]]) as usize;
                if 5 + name_len <= ext_val.len() {
                    let sni = String::from_utf8_lossy(&ext_val[5..5 + name_len]).to_string();
                    ctx.add_str(
                        Some(root),
                        "tls.handshake.extensions_server_name",
                        sni.clone(),
                        range,
                        None,
                    );
                    found_sni = Some(sni);
                }
            }
            // ALPN
            0x0010 if ext_val.len() >= 3 => {
                let mut p = 2usize;
                while p < ext_val.len() {
                    let l = ext_val[p] as usize;
                    p += 1;
                    if p + l > ext_val.len() {
                        break;
                    }
                    let alpn = String::from_utf8_lossy(&ext_val[p..p + l]).to_string();
                    ctx.add_str(
                        Some(root),
                        "tls.handshake.extensions_alpn_str",
                        alpn,
                        range,
                        None,
                    );
                    p += l;
                }
            }
            _ => {}
        }
        pos += ext_len;
    }
    found_sni
}

/// RFC 9000 QUIC v1 Packet Header dissector (`quic`, UDP 443).
pub struct QuicDissector {
    proto_id: ProtocolId,
}

impl QuicDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("QUIC IETF", "QUIC", "quic")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "quic.header_form",
            "Header Form",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(pid, "quic.version", "Version", FieldType::Uint32, "");
        let _ = reg.register_field(
            pid,
            "quic.dcid",
            "Destination Connection ID",
            FieldType::Bytes,
            "",
        );
        let _ = reg.register_field(
            pid,
            "quic.scid",
            "Source Connection ID",
            FieldType::Bytes,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for QuicDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (first, r_first) = buf.read_u8()?;
        let header_form = (first >> 7) & 1;

        let root = ctx.begin_protocol(self.proto_id, "QUIC IETF", buf.remaining_range());
        ctx.add_u64(
            Some(root),
            "quic.header_form",
            header_form as u64,
            r_first,
            None,
        );

        if header_form == 1 && buf.remaining() >= 6 {
            let (ver, r_ver) = buf.read_u32_be()?;
            let (dcid_len, _) = buf.read_u8()?;
            let (dcid, r_dcid) = buf.read_bytes((dcid_len as usize).min(20))?;
            let (scid_len, _) = buf.read_u8()?;
            let (scid, r_scid) = buf.read_bytes((scid_len as usize).min(20))?;

            ctx.add_u64(Some(root), "quic.version", ver as u64, r_ver, None);
            ctx.add_bytes(Some(root), "quic.dcid", dcid.to_vec(), r_dcid, None);
            ctx.add_bytes(Some(root), "quic.scid", scid.to_vec(), r_scid, None);
            ctx.set_info(format!("QUIC Long Header (version=0x{ver:08x})"));
        } else {
            ctx.set_info("QUIC Short Header (1-RTT ProtectedPayload)".to_string());
        }

        let _ = buf.read_bytes(buf.remaining())?;
        ctx.update_node_range(root, buf.range_from(start));
        Ok(Next::None)
    }
}

/// RFC 5905 Network Time Protocol (`ntp`, UDP 123).
pub struct NtpDissector {
    proto_id: ProtocolId,
}

impl NtpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Network Time Protocol", "NTP", "ntp")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "ntp.flags", "Flags", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ntp.stratum", "Stratum", FieldType::Uint8, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for NtpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (flags, r_f) = buf.read_u8()?;
        let (stratum, r_s) = buf.read_u8()?;
        let _ = buf.read_bytes(buf.remaining())?;
        let hdr_range = buf.range_from(start);

        let vn = (flags >> 3) & 0x07;
        let mode = flags & 0x07;
        let mode_str = match mode {
            3 => "client",
            4 => "server",
            5 => "broadcast",
            _ => "other",
        };
        let root = ctx.begin_protocol(self.proto_id, "Network Time Protocol", hdr_range);
        ctx.add_u64(Some(root), "ntp.flags", flags as u64, r_f, None);
        ctx.add_u64(Some(root), "ntp.stratum", stratum as u64, r_s, None);
        ctx.set_info(format!("NTP Version {vn}, {mode_str}, stratum {stratum}"));
        Ok(Next::None)
    }
}

/// Text-line / Banner protocol dissector for SSH (RFC 4253), FTP (RFC 959), SMTP (RFC 5321), and Syslog (RFC 5424).
pub struct TextProtocolDissector {
    proto_id: ProtocolId,
    short_name: &'static str,
    msg_field: &'static str,
}

impl TextProtocolDissector {
    pub fn register(
        reg: &mut Registry,
        full_name: &'static str,
        short_name: &'static str,
        filter_name: &'static str,
        msg_field: &'static str,
    ) -> ProtocolId {
        let pid = reg
            .register_protocol(full_name, short_name, filter_name)
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, msg_field, "Message", FieldType::String, "");
        pid
    }

    pub const fn new(
        proto_id: ProtocolId,
        short_name: &'static str,
        msg_field: &'static str,
    ) -> Self {
        Self {
            proto_id,
            short_name,
            msg_field,
        }
    }
}

impl Dissector for TextProtocolDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let (bytes, range) = buf.read_bytes(buf.remaining())?;
        let text = String::from_utf8_lossy(bytes);
        let first_line = text.lines().next().unwrap_or("").trim();
        let summary_line: String = first_line
            .chars()
            .filter(|c| !c.is_control())
            .take(96)
            .collect();

        let root = ctx.begin_protocol(self.proto_id, self.short_name, range);
        ctx.add_str(
            Some(root),
            self.msg_field,
            summary_line.clone(),
            range,
            None,
        );
        if !summary_line.is_empty() {
            ctx.set_info(format!("{}: {summary_line}", self.short_name));
        }
        Ok(Next::None)
    }
}
