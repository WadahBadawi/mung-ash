use mash_core::{ByteRange, FieldType, ProtocolId};
use mash_dissect::{
    DissectCtx, DissectResult, Dissector, Next, PacketCursor, Registry, TableId, TruncatedError,
};

pub fn ethertype_name(etype: u16) -> &'static str {
    match etype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x8035 => "RARP",
        0x8100 => "802.1Q Virtual LAN",
        0x86dd => "IPv6",
        0x8847 => "MPLS Unicast",
        0x8848 => "MPLS Multicast",
        0x8863 => "PPPoE Discovery",
        0x8864 => "PPPoE Session",
        0x888e => "802.1X Authentication",
        0x88a8 => "802.1ad Provider Bridge (QinQ)",
        0x88cc => "LLDP",
        0x88f7 => "PTP (IEEE 1588)",
        _ => "Unknown",
    }
}

/// IEEE 802.3 / Ethernet II dissector (`eth`).
pub struct EthernetDissector {
    proto_id: ProtocolId,
}

impl EthernetDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Ethernet II", "Ethernet", "eth")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "eth.dst",
            "Destination",
            FieldType::MacAddr,
            "Destination Hardware MAC Address",
        );
        let _ = reg.register_field(
            pid,
            "eth.src",
            "Source",
            FieldType::MacAddr,
            "Source Hardware MAC Address",
        );
        let _ = reg.register_field(
            pid,
            "eth.type",
            "Type",
            FieldType::Uint16,
            "EtherType payload identifier",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for EthernetDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (dst, r_dst) = buf.read_mac()?;
        let (src, r_src) = buf.read_mac()?;
        let (etype, r_type) = buf.read_u16_be()?;
        let hdr_range = buf.range_from(start);

        let src_str = ctx.resolver.format_mac(src);
        let dst_str = ctx.resolver.format_mac(dst);
        if ctx.summary.source.is_empty() {
            ctx.summary.source = src_str.clone();
            ctx.summary.destination = dst_str.clone();
        }

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Ethernet II, Src: {src_str}, Dst: {dst_str}"),
            hdr_range,
        );
        ctx.add_mac(
            Some(root),
            "eth.dst",
            dst,
            r_dst,
            Some(format!("Destination: {dst_str}")),
        );
        ctx.add_mac(
            Some(root),
            "eth.src",
            src,
            r_src,
            Some(format!("Source: {src_str}")),
        );
        ctx.add_u64(
            Some(root),
            "eth.type",
            etype as u64,
            r_type,
            Some(format!("Type: {} (0x{etype:04x})", ethertype_name(etype))),
        );
        ctx.set_info(format!(
            "Ethernet II {src_str} -> {dst_str} [0x{etype:04x}]"
        ));

        Ok(Next::Table(TableId::EtherType, etype as u32))
    }
}

/// IEEE 802.1Q / 802.1ad VLAN tag dissector (`vlan`).
pub struct VlanDissector {
    proto_id: ProtocolId,
}

impl VlanDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("802.1Q Virtual LAN", "VLAN", "vlan")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "vlan.priority",
            "Priority",
            FieldType::Uint8,
            "802.1p Priority Code Point (PCP)",
        );
        let _ = reg.register_field(
            pid,
            "vlan.dei",
            "DEI",
            FieldType::Bool,
            "Drop Eligible Indicator",
        );
        let _ = reg.register_field(
            pid,
            "vlan.id",
            "ID",
            FieldType::Uint16,
            "12-bit VLAN Identifier",
        );
        let _ = reg.register_field(
            pid,
            "vlan.etype",
            "Type",
            FieldType::Uint16,
            "Encapsulated EtherType",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for VlanDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let (tci, r_tci) = buf.read_u16_be()?;
        let (etype, r_etype) = buf.read_u16_be()?;
        let hdr_range = buf.range_from(start);

        let pcp = (tci >> 13) & 0x07;
        let dei = ((tci >> 12) & 0x01) != 0;
        let vid = tci & 0x0fff;

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("802.1Q Virtual LAN, PRI: {pcp}, DEI: {}, ID: {vid}", u8::from(dei)),
            hdr_range,
        );
        ctx.add_u64(
            Some(root),
            "vlan.priority",
            pcp as u64,
            r_tci.with_bitmask(0xe000),
            Some(format!("Priority: {pcp}")),
        );
        ctx.add_bool(
            Some(root),
            "vlan.dei",
            dei,
            r_tci.with_bitmask(0x1000),
            Some(format!("DEI: {dei}")),
        );
        ctx.add_u64(
            Some(root),
            "vlan.id",
            vid as u64,
            r_tci.with_bitmask(0x0fff),
            Some(format!("VLAN ID: {vid}")),
        );
        ctx.add_u64(
            Some(root),
            "vlan.etype",
            etype as u64,
            r_etype,
            Some(format!("Type: {} (0x{etype:04x})", ethertype_name(etype))),
        );

        Ok(Next::Table(TableId::EtherType, etype as u32))
    }
}

/// BSD Loopback / Null encapsulation (`null`, DLT_NULL = 0).
pub struct NullLoopbackDissector {
    proto_id: ProtocolId,
}

impl NullLoopbackDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("BSD Loopback / Null", "Null", "null")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "null.family",
            "Family",
            FieldType::Uint32,
            "BSD Address Family",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for NullLoopbackDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let (b, r) = buf.read_bytes(4)?;
        let le_val = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let be_val = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let family = if le_val <= 40 { le_val } else { be_val };

        let root = ctx.begin_protocol(
            self.proto_id,
            format!("Null/Loopback (Family: {family})"),
            r,
        );
        ctx.add_u64(Some(root), "null.family", family as u64, r, None);

        match family {
            2 => Ok(Next::Table(TableId::EtherType, 0x0800)),
            10 | 24 | 28 | 30 => Ok(Next::Table(TableId::EtherType, 0x86dd)),
            _ => Ok(Next::None),
        }
    }
}

/// Raw IP encapsulation (`raw`, DLT_RAW = 101 / 228 / 229).
pub struct RawIpDissector {
    proto_id: ProtocolId,
}

impl RawIpDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        reg.register_protocol("Raw IP", "Raw", "raw")
            .unwrap_or(ProtocolId(0))
    }

    pub const fn new(proto_id: ProtocolId) -> Self {
        Self { proto_id }
    }
}

impl Dissector for RawIpDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, _ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let first = buf.peek_u8()?;
        match first >> 4 {
            4 => Ok(Next::Table(TableId::EtherType, 0x0800)),
            6 => Ok(Next::Table(TableId::EtherType, 0x86dd)),
            _ => Err(TruncatedError {
                offset: buf.abs_offset(),
                needed: 20,
                available: buf.remaining(),
            }),
        }
    }
}

/// Linux Cooked Capture v1 & v2 (`sll`, DLT_LINUX_SLL = 113, DLT_LINUX_SLL2 = 276).
pub struct LinuxSllDissector {
    proto_id: ProtocolId,
    is_v2: bool,
}

impl LinuxSllDissector {
    pub fn register(reg: &mut Registry) -> ProtocolId {
        let pid = reg
            .register_protocol("Linux Cooked Capture", "SLL", "sll")
            .unwrap_or(ProtocolId(0));
        let _ = reg.register_field(
            pid,
            "sll.pkttype",
            "Packet Type",
            FieldType::Uint16,
            "Linux SLL packet direction/type",
        );
        let _ = reg.register_field(
            pid,
            "sll.etype",
            "Protocol",
            FieldType::Uint16,
            "Encapsulated EtherType",
        );
        pid
    }

    pub const fn new(proto_id: ProtocolId, is_v2: bool) -> Self {
        Self { proto_id, is_v2 }
    }
}

impl Dissector for LinuxSllDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        if self.is_v2 {
            // SLL2 is 20 bytes: protocol (2), reserved (2), ifindex (4), arphrd (2), pkttype (1), halen (1), addr (8)
            let (etype, r_etype) = buf.read_u16_be()?;
            let _ = buf.read_bytes(8)?;
            let (pkttype, r_pkt) = buf.read_u8()?;
            let _ = buf.read_bytes(9)?;
            let hdr_range = ByteRange::new(start, buf.abs_offset());
            let root = ctx.begin_protocol(self.proto_id, "Linux Cooked Capture v2", hdr_range);
            ctx.add_u64(Some(root), "sll.pkttype", pkttype as u64, r_pkt, None);
            ctx.add_u64(Some(root), "sll.etype", etype as u64, r_etype, None);
            Ok(Next::Table(TableId::EtherType, etype as u32))
        } else {
            // SLL1 is 16 bytes: pkttype (2), arphrd (2), halen (2), addr (8), protocol (2)
            let (pkttype, r_pkt) = buf.read_u16_be()?;
            let _ = buf.read_bytes(12)?;
            let (etype, r_etype) = buf.read_u16_be()?;
            let hdr_range = ByteRange::new(start, buf.abs_offset());
            let root = ctx.begin_protocol(self.proto_id, "Linux Cooked Capture v1", hdr_range);
            ctx.add_u64(Some(root), "sll.pkttype", pkttype as u64, r_pkt, None);
            ctx.add_u64(Some(root), "sll.etype", etype as u64, r_etype, None);
            Ok(Next::Table(TableId::EtherType, etype as u32))
        }
    }
}

