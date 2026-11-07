use mash_core::{FieldType, ProtocolId, Result};
use mash_dissect::{
    DissectCtx, DissectResult, Dissector, DissectorEngine, Next, PacketCursor, TableId,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Byte order for custom plugin fields (`EXT-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Endian {
    #[default]
    Big,
    Little,
}

/// Declarative field descriptor for a custom protocol plugin (`EXT-01`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomFieldSpec {
    pub abbrev: String,
    pub name: String,
    pub field_type: FieldType,
    pub byte_len: usize,
    #[serde(default)]
    pub endian: Endian,
}

/// Declarative custom protocol plugin specification (`EXT-01`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomProtocolSpec {
    pub name: String,
    pub short_name: String,
    pub filter_name: String,
    #[serde(default)]
    pub tcp_ports: Vec<u16>,
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    #[serde(default)]
    pub ethertypes: Vec<u16>,
    pub fields: Vec<CustomFieldSpec>,
}

/// Runtime dissector executing a sandboxed `CustomProtocolSpec` (`EXT-01`, `EXT-02`).
pub struct CustomPluginDissector {
    proto_id: ProtocolId,
    spec: CustomProtocolSpec,
}

impl CustomPluginDissector {
    /// Register a `CustomProtocolSpec` and all its fields + port bindings on `engine`.
    pub fn register_on_engine(
        engine: &mut DissectorEngine,
        spec: CustomProtocolSpec,
    ) -> Result<ProtocolId> {
        let pid = engine.registry.register_protocol(
            spec.name.clone(),
            spec.short_name.clone(),
            spec.filter_name.clone(),
        )?;
        for f in &spec.fields {
            engine.registry.register_field(
                pid,
                f.abbrev.clone(),
                f.name.clone(),
                f.field_type,
                "Custom plugin field",
            )?;
        }
        for &port in &spec.tcp_ports {
            engine.register_table_entry(TableId::TcpPort, port as u32, pid);
        }
        for &port in &spec.udp_ports {
            engine.register_table_entry(TableId::UdpPort, port as u32, pid);
        }
        for &et in &spec.ethertypes {
            engine.register_table_entry(TableId::EtherType, et as u32, pid);
        }
        engine.register_dissector(Arc::new(Self {
            proto_id: pid,
            spec,
        }));
        Ok(pid)
    }
}

impl Dissector for CustomPluginDissector {
    fn protocol(&self) -> ProtocolId {
        self.proto_id
    }

    fn dissect(&self, ctx: &mut DissectCtx<'_>, buf: &mut PacketCursor<'_>) -> DissectResult {
        let start = buf.abs_offset();
        let root = ctx.begin_protocol(
            self.proto_id,
            self.spec.name.clone(),
            buf.remaining_range(),
        );

        let mut summary_items = Vec::new();
        for f in self.spec.fields.iter().take(128) {
            if buf.remaining() < f.byte_len {
                break;
            }
            match f.field_type {
                FieldType::Uint8 | FieldType::Bool => {
                    let (v, r) = buf.read_u8()?;
                    ctx.add_u64(Some(root), &f.abbrev, v as u64, r, None);
                    summary_items.push(format!("{}={v}", f.name));
                }
                FieldType::Uint16 => {
                    let (v, r) = match f.endian {
                        Endian::Big => buf.read_u16_be()?,
                        Endian::Little => buf.read_u16_le()?,
                    };
                    ctx.add_u64(Some(root), &f.abbrev, v as u64, r, None);
                    summary_items.push(format!("{}={v}", f.name));
                }
                FieldType::Uint32 => {
                    let (v, r) = match f.endian {
                        Endian::Big => buf.read_u32_be()?,
                        Endian::Little => buf.read_u32_le()?,
                    };
                    ctx.add_u64(Some(root), &f.abbrev, v as u64, r, None);
                    summary_items.push(format!("{}={v}", f.name));
                }
                FieldType::String => {
                    let (b, r) = buf.read_bytes(f.byte_len)?;
                    let s = String::from_utf8_lossy(b)
                        .trim_end_matches('\0')
                        .to_string();
                    ctx.add_str(Some(root), &f.abbrev, s.clone(), r, None);
                    summary_items.push(format!("{}={s}", f.name));
                }
                _ => {
                    let (b, r) = buf.read_bytes(f.byte_len)?;
                    ctx.add_bytes(Some(root), &f.abbrev, b.to_vec(), r, None);
                }
            }
        }

        let _ = buf.read_bytes(buf.remaining())?;
        ctx.update_node_range(root, buf.range_from(start));
        ctx.set_info(format!(
            "{} ({})",
            self.spec.short_name,
            summary_items.join(", ")
        ));
        Ok(Next::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mash_core::{Frame, LinkType, NameResolver, ResolutionConfig, Timestamp};
    use mash_dissect::ConversationTracker;

    #[test]
    fn custom_plugin_registers_and_dissects_protocol() {
        let mut engine = DissectorEngine::new();
        let spec = CustomProtocolSpec {
            name: "Acme Telemetry Protocol".to_string(),
            short_name: "ACME".to_string(),
            filter_name: "acme".to_string(),
            tcp_ports: Vec::new(),
            udp_ports: Vec::new(),
            ethertypes: vec![0x88b5],
            fields: vec![
                CustomFieldSpec {
                    abbrev: "acme.version".to_string(),
                    name: "Version".to_string(),
                    field_type: FieldType::Uint8,
                    byte_len: 1,
                    endian: Endian::Big,
                },
                CustomFieldSpec {
                    abbrev: "acme.seq".to_string(),
                    name: "Seq".to_string(),
                    field_type: FieldType::Uint16,
                    byte_len: 2,
                    endian: Endian::Big,
                },
            ],
        };
        let pid = CustomPluginDissector::register_on_engine(&mut engine, spec).unwrap();
        engine.register_table_entry(TableId::LinkType, LinkType::Ethernet.to_u32(), pid);

        let frame = Frame::new(1, Timestamp::ZERO, LinkType::Ethernet, vec![2, 0x01, 0x00]);
        let mut resolver = NameResolver::new(ResolutionConfig::default());
        let mut conv = ConversationTracker::new();
        let pkt = engine.dissect_frame(&frame, None, None, &mut resolver, &mut conv);

        assert_eq!(pkt.summary.protocol, "ACME");
        assert_eq!(
            pkt.tree
                .by_abbrev("acme.seq")
                .next()
                .unwrap()
                .value
                .as_u64(),
            Some(256)
        );
    }
}

