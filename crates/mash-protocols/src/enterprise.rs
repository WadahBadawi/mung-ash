use mash_core::{ByteRange, ExpertGroup, ExpertSeverity, FieldType, ProtocolId};
use mash_dissect::{DissectCtx, DissectResult, Dissector, Next, PacketCursor, Registry};
use std::net::Ipv4Addr;

// ============================================================================
// 1. BGPv4 Dissector (RFC 4271, TCP Port 179)
// ============================================================================

pub struct BgpDissector {
    proto_id: ProtocolId,
}

impl BgpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Border Gateway Protocol", "BGP", "bgp")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "bgp.type", "Message Type", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "bgp.length", "Length", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "bgp.version", "Version", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "bgp.my_as", "My AS", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "bgp.hold_time", "Hold Time", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "bgp.identifier", "BGP Identifier", FieldType::Ipv4, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn bgp_type_name(t: u8) -> &'static str {
    match t {
        1 => "OPEN",
        2 => "UPDATE",
        3 => "NOTIFICATION",
        4 => "KEEPALIVE",
        5 => "ROUTE-REFRESH",
        _ => "UNKNOWN",
    }
}

impl Dissector for BgpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let base = buf.abs_offset();
        let total = buf.remaining();
        let (marker, r_marker) = buf.read_bytes(16)?;
        let (length, r_len) = buf.read_u16_be()?;
        let (msg_type, r_type) = buf.read_u8()?;

        let tname = bgp_type_name(msg_type);
        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Border Gateway Protocol - {tname} Message"),
            ByteRange::with_source(buf.source_idx(), base, base + total),
        );

        if marker != [0xff; 16] {
            ctx.add_expert(
                root,
                ExpertSeverity::Warn,
                ExpertGroup::Malformed,
                "BGP marker is not all 0xFF bytes".to_string(),
                r_marker,
            );
        }

        ctx.add_u64(
            Some(root),
            "bgp.length",
            length as u64,
            r_len,
            Some(format!("Length: {length}")),
        );
        ctx.add_u64(
            Some(root),
            "bgp.type",
            msg_type as u64,
            r_type,
            Some(format!("Type: {tname} ({msg_type})")),
        );

        let mut info = format!("{tname} Message");
        if msg_type == 1 && buf.remaining() >= 10 {
            let (ver, r_ver) = buf.read_u8()?;
            let (my_as, r_as) = buf.read_u16_be()?;
            let (hold, r_hold) = buf.read_u16_be()?;
            let (id_bytes, r_id) = buf.read_bytes(4)?;
            let bgp_id = Ipv4Addr::new(id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]);
            ctx.add_u64(Some(root), "bgp.version", ver as u64, r_ver, None);
            ctx.add_u64(Some(root), "bgp.my_as", my_as as u64, r_as, None);
            ctx.add_u64(Some(root), "bgp.hold_time", hold as u64, r_hold, None);
            ctx.add_ipv4(Some(root), "bgp.identifier", bgp_id.octets(), r_id, None);
            info = format!("OPEN Message (AS{my_as}, ID {bgp_id})");
        }

        ctx.set_protocol_column("BGP");
        ctx.set_info(info);
        Ok(Next::None)
    }
}

// ============================================================================
// 2. OSPFv2 / OSPFv3 Dissector (RFC 2328 / RFC 5340, IP Protocol 89)
// ============================================================================

pub struct OspfDissector {
    proto_id: ProtocolId,
}

impl OspfDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Open Shortest Path First", "OSPF", "ospf")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "ospf.version", "OSPF Version", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "ospf.msg_type", "Message Type", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "ospf.packet_length",
            "Packet Length",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "ospf.router_id", "Source OSPF Router", FieldType::Ipv4, "");
        let _ = reg.register_field(pid, "ospf.area_id", "Area ID", FieldType::Ipv4, "");
        let _ = reg.register_field(pid, "ospf.checksum", "Checksum", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "ospf.auth_type", "Auth Type", FieldType::Uint16, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn ospf_type_name(t: u8) -> &'static str {
    match t {
        1 => "Hello Packet",
        2 => "DB Description",
        3 => "LS Request",
        4 => "LS Update",
        5 => "LS Acknowledge",
        _ => "Unknown Packet",
    }
}

impl Dissector for OspfDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let base = buf.abs_offset();
        let total = buf.remaining();
        let (ver, r_ver) = buf.read_u8()?;
        let (msg_type, r_type) = buf.read_u8()?;
        let (pkt_len, r_len) = buf.read_u16_be()?;
        let (rid_b, r_rid) = buf.read_bytes(4)?;
        let (aid_b, r_aid) = buf.read_bytes(4)?;
        let (csum, r_csum) = buf.read_u16_be()?;
        let (auth, r_auth) = buf.read_u16_be()?;

        let router_id = Ipv4Addr::new(rid_b[0], rid_b[1], rid_b[2], rid_b[3]);
        let area_id = Ipv4Addr::new(aid_b[0], aid_b[1], aid_b[2], aid_b[3]);
        let tname = ospf_type_name(msg_type);

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Open Shortest Path First v{ver} ({tname})"),
            ByteRange::with_source(buf.source_idx(), base, base + total),
        );
        ctx.add_u64(Some(root), "ospf.version", ver as u64, r_ver, None);
        ctx.add_u64(
            Some(root),
            "ospf.msg_type",
            msg_type as u64,
            r_type,
            Some(format!("Message Type: {tname} ({msg_type})")),
        );
        ctx.add_u64(Some(root), "ospf.packet_length", pkt_len as u64, r_len, None);
        ctx.add_ipv4(Some(root), "ospf.router_id", router_id.octets(), r_rid, None);
        ctx.add_ipv4(Some(root), "ospf.area_id", area_id.octets(), r_aid, None);
        ctx.add_u64(
            Some(root),
            "ospf.checksum",
            csum as u64,
            r_csum,
            Some(format!("Checksum: 0x{csum:04x}")),
        );
        ctx.add_u64(Some(root), "ospf.auth_type", auth as u64, r_auth, None);

        ctx.set_protocol_column("OSPF");
        ctx.set_info(format!("{tname} (Router {router_id}, Area {area_id})"));
        Ok(Next::None)
    }
}

// ============================================================================
// 3. DHCPv6 Dissector (RFC 8415, UDP Ports 546, 547)
// ============================================================================

pub struct Dhcpv6Dissector {
    proto_id: ProtocolId,
}

impl Dhcpv6Dissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("DHCPv6", "DHCPv6", "dhcpv6")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "dhcpv6.msgtype", "Message Type", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "dhcpv6.xid", "Transaction ID", FieldType::Uint32, "");
        let _ = reg.register_field(
            pid,
            "dhcpv6.option.type",
            "Option Code",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "dhcpv6.option.len",
            "Option Length",
            FieldType::Uint16,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn dhcpv6_msg_name(t: u8) -> &'static str {
    match t {
        1 => "Solicit",
        2 => "Advertise",
        3 => "Request",
        4 => "Confirm",
        5 => "Renew",
        6 => "Rebind",
        7 => "Reply",
        8 => "Release",
        9 => "Decline",
        10 => "Reconfigure",
        11 => "Information-request",
        12 => "Relay-forw",
        13 => "Relay-repl",
        _ => "Unknown",
    }
}

impl Dissector for Dhcpv6Dissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let base = buf.abs_offset();
        let total = buf.remaining();
        let (msg_type, r_type) = buf.read_u8()?;
        let (xid_bytes, r_xid) = buf.read_bytes(3)?;
        let xid = ((xid_bytes[0] as u32) << 16)
            | ((xid_bytes[1] as u32) << 8)
            | (xid_bytes[2] as u32);
        let mname = dhcpv6_msg_name(msg_type);

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("DHCPv6 ({mname})"),
            ByteRange::with_source(buf.source_idx(), base, base + total),
        );
        ctx.add_u64(
            Some(root),
            "dhcpv6.msgtype",
            msg_type as u64,
            r_type,
            Some(format!("Message Type: {mname} ({msg_type})")),
        );
        ctx.add_u64(
            Some(root),
            "dhcpv6.xid",
            xid as u64,
            r_xid,
            Some(format!("Transaction ID: 0x{xid:06x}")),
        );

        let mut opt_guard = 0usize;
        while buf.remaining() >= 4 && opt_guard < 64 {
            opt_guard += 1;
            let (opt_code, r_oc) = buf.read_u16_be()?;
            let (opt_len, r_ol) = buf.read_u16_be()?;
            ctx.add_u64(Some(root), "dhcpv6.option.type", opt_code as u64, r_oc, None);
            ctx.add_u64(Some(root), "dhcpv6.option.len", opt_len as u64, r_ol, None);
            if buf.remaining() < opt_len as usize {
                break;
            }
            let _ = buf.read_bytes(opt_len as usize)?;
        }

        ctx.set_protocol_column("DHCPv6");
        ctx.set_info(format!("{mname} XID: 0x{xid:06x}"));
        Ok(Next::None)
    }
}

// ============================================================================
// 4. SMB2 / SMB3 Dissector (MS-SMB2, TCP Port 445)
// ============================================================================

pub struct Smb2Dissector {
    proto_id: ProtocolId,
}

impl Smb2Dissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Server Message Block Protocol v2/v3", "SMB2", "smb2")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "smb2.cmd", "Command", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "smb2.nt_status", "NT Status", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "smb2.flags", "Flags", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "smb2.msg_id", "Message ID", FieldType::Uint64, "");
        let _ = reg.register_field(pid, "smb2.tree_id", "Tree ID", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "smb2.ses_id", "Session ID", FieldType::Uint64, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn smb2_cmd_name(cmd: u16) -> &'static str {
    match cmd {
        0x0000 => "Negotiate Protocol",
        0x0001 => "Session Setup",
        0x0002 => "Session Logoff",
        0x0003 => "Tree Connect",
        0x0004 => "Tree Disconnect",
        0x0005 => "Create",
        0x0006 => "Close",
        0x0007 => "Flush",
        0x0008 => "Read",
        0x0009 => "Write",
        0x000a => "Lock",
        0x000b => "Ioctl",
        0x000c => "Cancel",
        0x000d => "KeepAlive",
        0x000e => "Find",
        0x000f => "Notify",
        0x0010 => "GetInfo",
        0x0011 => "SetInfo",
        0x0012 => "Break",
        _ => "Unknown Command",
    }
}

impl Dissector for Smb2Dissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        // Optional 4-byte NetBIOS session service length header
        if buf.remaining() >= 68 && buf.slice_remaining()[0] == 0x00 {
            let nb_check = &buf.slice_remaining()[4..8];
            if nb_check == b"\xfeSMB" || nb_check == b"\xfdSMB" {
                let _ = buf.read_u32_be()?;
            }
        }
        let base = buf.abs_offset();
        let total = buf.remaining();
        let (magic, _) = buf.read_bytes(4)?;
        if magic != b"\xfeSMB" && magic != b"\xfdSMB" {
            return Ok(Next::None);
        }

        let root = ctx.begin_protocol(
            self.proto_id,
            "Server Message Block Protocol v2/v3",
            ByteRange::with_source(buf.source_idx(), base, base + total),
        );

        if magic == b"\xfdSMB" {
            ctx.set_protocol_column("SMB3");
            ctx.set_info("Encrypted SMB3 Transform Header");
            return Ok(Next::None);
        }

        let _struct_size = buf.read_u16_le()?;
        let _credit_charge = buf.read_u16_le()?;
        let (nt_status, r_status) = buf.read_u32_le()?;
        let (cmd, r_cmd) = buf.read_u16_le()?;
        let _credits = buf.read_u16_le()?;
        let (flags, r_flags) = buf.read_u32_le()?;
        let _next_cmd = buf.read_u32_le()?;
        let (mid_b, r_mid) = buf.read_bytes(8)?;
        let msg_id = u64::from_le_bytes([
            mid_b[0], mid_b[1], mid_b[2], mid_b[3], mid_b[4], mid_b[5], mid_b[6], mid_b[7],
        ]);
        let _reserved = buf.read_u32_le()?;
        let (tree_id, r_tid) = buf.read_u32_le()?;
        let (sid_b, r_sid) = buf.read_bytes(8)?;
        let ses_id = u64::from_le_bytes([
            sid_b[0], sid_b[1], sid_b[2], sid_b[3], sid_b[4], sid_b[5], sid_b[6], sid_b[7],
        ]);

        let cname = smb2_cmd_name(cmd);
        let is_resp = (flags & 0x0000_0001) != 0;
        ctx.add_u64(
            Some(root),
            "smb2.cmd",
            cmd as u64,
            r_cmd,
            Some(format!("Command: {cname} ({cmd})")),
        );
        ctx.add_u64(
            Some(root),
            "smb2.nt_status",
            nt_status as u64,
            r_status,
            Some(format!("NT Status: 0x{nt_status:08x}")),
        );
        ctx.add_u64(Some(root), "smb2.flags", flags as u64, r_flags, None);
        ctx.add_u64(Some(root), "smb2.msg_id", msg_id, r_mid, None);
        ctx.add_u64(Some(root), "smb2.tree_id", tree_id as u64, r_tid, None);
        ctx.add_u64(Some(root), "smb2.ses_id", ses_id, r_sid, None);

        ctx.set_protocol_column("SMB2");
        ctx.set_info(format!(
            "{cname} {}",
            if is_resp { "Response" } else { "Request" }
        ));
        Ok(Next::None)
    }
}

// ============================================================================
// 5. gRPC & Protobuf Wire Framing Dissector (TCP Port 50051)
// ============================================================================

pub struct GrpcDissector {
    proto_id: ProtocolId,
}

impl GrpcDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("gRPC / Protocol Buffers", "gRPC", "grpc")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "grpc.compressed",
            "Compressed Flag",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(pid, "grpc.length", "Message Length", FieldType::Uint32, "");
        let _ = reg.register_field(
            pid,
            "grpc.protobuf.field_number",
            "Protobuf Field Number",
            FieldType::Uint32,
            "",
        );
        let _ = reg.register_field(
            pid,
            "grpc.protobuf.wire_type",
            "Protobuf Wire Type",
            FieldType::Uint8,
            "",
        );
        let _ = reg.register_field(
            pid,
            "grpc.protobuf.varint",
            "Protobuf Varint Value",
            FieldType::Uint64,
            "",
        );
        let _ = reg.register_field(
            pid,
            "grpc.protobuf.string",
            "Protobuf String Value",
            FieldType::String,
            "",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn read_varint(slice: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while *pos < slice.len() && shift < 64 {
        let b = slice[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

impl Dissector for GrpcDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let base = buf.abs_offset();
        let total = buf.remaining();
        let (comp_flag, r_comp) = buf.read_u8()?;
        let (msg_len, r_len) = buf.read_u32_be()?;

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("gRPC Message ({msg_len} bytes)"),
            ByteRange::with_source(buf.source_idx(), base, base + total),
        );
        ctx.add_u64(
            Some(root),
            "grpc.compressed",
            comp_flag as u64,
            r_comp,
            None,
        );
        ctx.add_u64(Some(root), "grpc.length", msg_len as u64, r_len, None);

        let body_len = (msg_len as usize).min(buf.remaining());
        let (body, r_body) = buf.read_bytes(body_len)?;
        if comp_flag == 0 {
            let mut p = 0usize;
            let mut fields_decoded = 0usize;
            while p < body.len() && fields_decoded < 32 {
                let Some(tag) = read_varint(body, &mut p) else {
                    break;
                };
                let wire_type = (tag & 0x07) as u8;
                let field_no = (tag >> 3) as u32;
                if field_no == 0 {
                    break;
                }
                ctx.add_u64(
                    Some(root),
                    "grpc.protobuf.field_number",
                    field_no as u64,
                    r_body,
                    None,
                );
                ctx.add_u64(
                    Some(root),
                    "grpc.protobuf.wire_type",
                    wire_type as u64,
                    r_body,
                    None,
                );
                match wire_type {
                    0 => {
                        let Some(val) = read_varint(body, &mut p) else {
                            break;
                        };
                        ctx.add_u64(Some(root), "grpc.protobuf.varint", val, r_body, None);
                    }
                    1 => {
                        if p + 8 > body.len() {
                            break;
                        }
                        p += 8;
                    }
                    2 => {
                        let Some(len) = read_varint(body, &mut p) else {
                            break;
                        };
                        let l = len as usize;
                        if p + l > body.len() {
                            break;
                        }
                        if let Ok(s) = std::str::from_utf8(&body[p..p + l]) {
                            ctx.add_str(Some(root), "grpc.protobuf.string", s.to_string(), r_body, None);
                        }
                        p += l;
                    }
                    5 => {
                        if p + 4 > body.len() {
                            break;
                        }
                        p += 4;
                    }
                    _ => break,
                }
                fields_decoded += 1;
            }
        }

        ctx.set_protocol_column("gRPC");
        ctx.set_info(format!(
            "gRPC Frame (len={msg_len}, compressed={comp_flag})"
        ));
        Ok(Next::None)
    }
}

// ============================================================================
// 6. MQTT v3.1.1 / v5.0 Dissector (TCP Ports 1883, 8883)
// ============================================================================

pub struct MqttDissector {
    proto_id: ProtocolId,
}

impl MqttDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("MQ Telemetry Transport Protocol", "MQTT", "mqtt")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(pid, "mqtt.msgtype", "Message Type", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "mqtt.qos", "QoS Level", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "mqtt.retain", "Retain", FieldType::Bool, "");
        let _ = reg.register_field(pid, "mqtt.len", "Remaining Length", FieldType::Uint32, "");
        let _ = reg.register_field(pid, "mqtt.topic", "Topic Name", FieldType::String, "");
        let _ = reg.register_field(pid, "mqtt.proto_name", "Protocol Name", FieldType::String, "");
        let _ = reg.register_field(pid, "mqtt.ver", "Version", FieldType::Uint8, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn mqtt_type_name(t: u8) -> &'static str {
    match t {
        1 => "Connect Command",
        2 => "Connect Ack",
        3 => "Publish Message",
        4 => "Publish Ack",
        5 => "Publish Received",
        6 => "Publish Release",
        7 => "Publish Complete",
        8 => "Subscribe Request",
        9 => "Subscribe Ack",
        10 => "Unsubscribe Request",
        11 => "Unsubscribe Ack",
        12 => "Ping Request",
        13 => "Ping Response",
        14 => "Disconnect Req",
        15 => "Auth",
        _ => "Reserved",
    }
}

impl Dissector for MqttDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let base = buf.abs_offset();
        let total = buf.remaining();
        let (hdr_byte, r_hdr) = buf.read_u8()?;
        let msg_type = hdr_byte >> 4;
        let qos = (hdr_byte >> 1) & 0x03;
        let retain = (hdr_byte & 0x01) != 0;

        // Decode MQTT variable-byte Remaining Length
        let mut rem_len = 0u32;
        let mut mult = 1u32;
        let len_start = buf.abs_offset();
        for _ in 0..4 {
            let (b, _) = buf.read_u8()?;
            rem_len += ((b & 0x7f) as u32) * mult;
            if (b & 0x80) == 0 {
                break;
            }
            mult *= 128;
        }
        let r_len = ByteRange::with_source(buf.source_idx(), len_start, buf.abs_offset());
        let tname = mqtt_type_name(msg_type);

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("MQ Telemetry Transport Protocol ({tname})"),
            ByteRange::with_source(buf.source_idx(), base, base + total),
        );
        ctx.add_u64(
            Some(root),
            "mqtt.msgtype",
            msg_type as u64,
            r_hdr,
            Some(format!("Message Type: {tname} ({msg_type})")),
        );
        ctx.add_u64(Some(root), "mqtt.qos", qos as u64, r_hdr, None);
        ctx.add_bool(Some(root), "mqtt.retain", retain, r_hdr, None);
        ctx.add_u64(Some(root), "mqtt.len", rem_len as u64, r_len, None);

        let mut info = tname.to_string();
        if msg_type == 1 && buf.remaining() >= 6 {
            let (plen, _) = buf.read_u16_be()?;
            if buf.remaining() > (plen as usize) {
                let (pname_b, r_pn) = buf.read_bytes(plen as usize)?;
                let pname = String::from_utf8_lossy(pname_b).to_string();
                let (ver, r_ver) = buf.read_u8()?;
                ctx.add_str(Some(root), "mqtt.proto_name", pname.clone(), r_pn, None);
                ctx.add_u64(Some(root), "mqtt.ver", ver as u64, r_ver, None);
                info = format!("Connect Command ({pname} v{ver})");
            }
        } else if msg_type == 3 && buf.remaining() >= 2 {
            let (tlen, _) = buf.read_u16_be()?;
            if buf.remaining() >= tlen as usize {
                let (topic_b, r_top) = buf.read_bytes(tlen as usize)?;
                let topic = String::from_utf8_lossy(topic_b).to_string();
                ctx.add_str(Some(root), "mqtt.topic", topic.clone(), r_top, None);
                info = format!("Publish Message [{topic}]");
            }
        }

        ctx.set_protocol_column("MQTT");
        ctx.set_info(info);
        Ok(Next::None)
    }
}

// ============================================================================
// 7. Modbus/TCP Dissector (TCP Port 502)
// ============================================================================

pub struct ModbusTcpDissector {
    proto_id: ProtocolId,
}

impl ModbusTcpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Modbus/TCP", "Modbus/TCP", "modbus")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "modbus.trans_id",
            "Transaction Identifier",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(
            pid,
            "modbus.proto_id",
            "Protocol Identifier",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "modbus.len", "Length", FieldType::Uint16, "");
        let _ = reg.register_field(pid, "modbus.unit_id", "Unit Identifier", FieldType::Uint8, "");
        let _ = reg.register_field(pid, "modbus.func_code", "Function Code", FieldType::Uint8, "");
        let _ = reg.register_field(
            pid,
            "modbus.reference_num",
            "Reference Number",
            FieldType::Uint16,
            "",
        );
        let _ = reg.register_field(pid, "modbus.word_cnt", "Word Count", FieldType::Uint16, "");
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

fn modbus_func_name(fc: u8) -> &'static str {
    match fc & 0x7f {
        1 => "Read Coils",
        2 => "Read Discrete Inputs",
        3 => "Read Holding Registers",
        4 => "Read Input Registers",
        5 => "Write Single Coil",
        6 => "Write Single Register",
        15 => "Write Multiple Coils",
        16 => "Write Multiple Registers",
        _ => "Function",
    }
}

impl Dissector for ModbusTcpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let base = buf.abs_offset();
        let total = buf.remaining();
        let (tid, r_tid) = buf.read_u16_be()?;
        let (pid, r_pid) = buf.read_u16_be()?;
        let (len, r_len) = buf.read_u16_be()?;
        let (uid, r_uid) = buf.read_u8()?;
        let (fc, r_fc) = buf.read_u8()?;

        let fname = modbus_func_name(fc);
        let is_exc = (fc & 0x80) != 0;

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Modbus/TCP ({fname})"),
            ByteRange::with_source(buf.source_idx(), base, base + total),
        );
        ctx.add_u64(Some(root), "modbus.trans_id", tid as u64, r_tid, None);
        ctx.add_u64(Some(root), "modbus.proto_id", pid as u64, r_pid, None);
        ctx.add_u64(Some(root), "modbus.len", len as u64, r_len, None);
        ctx.add_u64(Some(root), "modbus.unit_id", uid as u64, r_uid, None);
        ctx.add_u64(
            Some(root),
            "modbus.func_code",
            fc as u64,
            r_fc,
            Some(format!("Function Code: {fname} ({fc})")),
        );

        if is_exc {
            ctx.add_expert(
                root,
                ExpertSeverity::Warn,
                ExpertGroup::ResponseCode,
                format!("Modbus Exception Response for {fname}"),
                r_fc,
            );
        } else if buf.remaining() >= 4 {
            let (ref_num, r_ref) = buf.read_u16_be()?;
            let (wcnt, r_wcnt) = buf.read_u16_be()?;
            ctx.add_u64(
                Some(root),
                "modbus.reference_num",
                ref_num as u64,
                r_ref,
                None,
            );
            ctx.add_u64(Some(root), "modbus.word_cnt", wcnt as u64, r_wcnt, None);
        }

        ctx.set_protocol_column("Modbus/TCP");
        ctx.set_info(format!(
            "Trans: {tid}; Unit: {uid}, Func: {fc}: {fname}{}",
            if is_exc { " [Exception]" } else { "" }
        ));
        Ok(Next::None)
    }
}
