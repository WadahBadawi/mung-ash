use mash_core::{Frame, LinkType, Timestamp};

/// Options for importing a hex dump into synthetic frames (`FIL-06` / `mash-text2pcap`).
#[derive(Debug, Clone)]
pub struct Text2PcapOptions {
    pub link_type: LinkType,
    pub prepend_ethernet: Option<u16>,
    pub prepend_ipv4_proto: Option<u8>,
    pub prepend_udp_ports: Option<(u16, u16)>,
    pub prepend_tcp_ports: Option<(u16, u16)>,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

impl Default for Text2PcapOptions {
    fn default() -> Self {
        Self {
            link_type: LinkType::Ethernet,
            prepend_ethernet: None,
            prepend_ipv4_proto: None,
            prepend_udp_ports: None,
            prepend_tcp_ports: None,
            src_ip: [10, 1, 1, 1],
            dst_ip: [10, 1, 1, 2],
            src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        }
    }
}

/// Parse one or more packets from a hex dump text (like `od -Ax -tx1` or Wireshark's Export Packet Bytes).
/// A new offset `0000` (after bytes have already been accumulated) starts a new packet.
pub fn parse_hexdump_packets(input: &str, opts: &Text2PcapOptions) -> Vec<Frame> {
    let mut raw_packets: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let mut tokens = trimmed.split_whitespace();
        let Some(first) = tokens.next() else {
            continue;
        };
        let offset_clean = first.trim_end_matches(':');
        if let Ok(offset) = usize::from_str_radix(offset_clean, 16) {
            if offset == 0 && !current.is_empty() {
                raw_packets.push(std::mem::take(&mut current));
            }
            for tok in tokens {
                if tok.len() == 2 {
                    if let Ok(b) = u8::from_str_radix(tok, 16) {
                        current.push(b);
                        continue;
                    }
                }
                // Reached the ASCII dump column at the end of the line
                break;
            }
        }
    }
    if !current.is_empty() {
        raw_packets.push(current);
    }

    raw_packets
        .into_iter()
        .enumerate()
        .map(|(idx, payload)| {
            let data = wrap_synthetic_headers(payload, opts, idx as u32);
            Frame::new(
                (idx + 1) as u64,
                Timestamp::from_secs_nanos(idx as u64, 0),
                opts.link_type,
                data,
            )
        })
        .collect()
}

fn wrap_synthetic_headers(mut payload: Vec<u8>, opts: &Text2PcapOptions, seq_idx: u32) -> Vec<u8> {
    let mut ip_proto = opts.prepend_ipv4_proto;

    if let Some((sport, dport)) = opts.prepend_udp_ports {
        let udp_len = (8 + payload.len()).min(u16::MAX as usize) as u16;
        let mut udp = Vec::with_capacity(8 + payload.len());
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum 0
        udp.extend_from_slice(&payload);
        payload = udp;
        ip_proto = Some(17);
    } else if let Some((sport, dport)) = opts.prepend_tcp_ports {
        let mut tcp = Vec::with_capacity(20 + payload.len());
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&(seq_idx * 1000 + 1).to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.push(0x50); // data offset = 5 (20 bytes)
        tcp.push(0x18); // PSH | ACK
        tcp.extend_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum
        tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        tcp.extend_from_slice(&payload);
        payload = tcp;
        ip_proto = Some(6);
    }

    let mut ethertype = opts.prepend_ethernet;
    if let Some(proto) = ip_proto {
        let total_len = (20 + payload.len()).min(u16::MAX as usize) as u16;
        let mut ip = Vec::with_capacity(20 + payload.len());
        ip.push(0x45); // Version 4, IHL 5
        ip.push(0x00); // DSCP/ECN
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&(seq_idx as u16 + 1).to_be_bytes()); // ID
        ip.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
        ip.push(64); // TTL
        ip.push(proto);
        ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        ip.extend_from_slice(&opts.src_ip);
        ip.extend_from_slice(&opts.dst_ip);
        let csum = ipv4_checksum(&ip[..20]);
        ip[10] = (csum >> 8) as u8;
        ip[11] = (csum & 0xff) as u8;
        ip.extend_from_slice(&payload);
        payload = ip;
        if ethertype.is_none() {
            ethertype = Some(0x0800);
        }
    }

    if let Some(etype) = ethertype {
        let mut eth = Vec::with_capacity(14 + payload.len());
        eth.extend_from_slice(&opts.dst_mac);
        eth.extend_from_slice(&opts.src_mac);
        eth.extend_from_slice(&etype.to_be_bytes());
        eth.extend_from_slice(&payload);
        payload = eth;
    }

    payload
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        sum += word;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

