pub mod application;
pub mod link;
pub mod network;
pub mod transport;

use application::{
    DhcpDissector, DnsDissector, HttpDissector, NtpDissector, QuicDissector, TextProtocolDissector,
    TlsDissector,
};
use link::{
    EthernetDissector, LinuxSllDissector, NullLoopbackDissector, RawIpDissector, VlanDissector,
};
use mash_core::LinkType;
use mash_dissect::{DissectorEngine, TableId};
use network::{
    ArpDissector, GreDissector, IcmpDissector, Icmpv6Dissector, IgmpDissector, Ipv4Dissector,
    Ipv6Dissector, MplsDissector,
};
use std::sync::Arc;
use transport::{TcpDissector, UdpDissector, VxlanDissector};

/// Create a `DissectorEngine` populated with all built-in Tier-1 and Tier-2 dissectors.
pub fn build_default_engine() -> DissectorEngine {
    let mut engine = DissectorEngine::new();
    register_all_protocols(&mut engine);
    engine
}

/// Register all built-in protocols, fields, selector tables, and heuristics on `engine`.
pub fn register_all_protocols(engine: &mut DissectorEngine) {
    // 1. Link layer
    let eth_id = EthernetDissector::register(&mut engine.registry);
    let vlan_id = VlanDissector::register(&mut engine.registry);
    let null_id = NullLoopbackDissector::register(&mut engine.registry);
    let raw_id = RawIpDissector::register(&mut engine.registry);
    let sll_id = LinuxSllDissector::register(&mut engine.registry);
    let sll2_id = engine
        .registry
        .register_protocol("Linux Cooked Capture v2", "SLL2", "sll2")
        .unwrap();

    engine.register_dissector(Arc::new(EthernetDissector::new(eth_id)));
    engine.register_dissector(Arc::new(VlanDissector::new(vlan_id)));
    engine.register_dissector(Arc::new(NullLoopbackDissector::new(null_id)));
    engine.register_dissector(Arc::new(RawIpDissector::new(raw_id)));
    engine.register_dissector(Arc::new(LinuxSllDissector::new(sll_id, false)));
    engine.register_dissector(Arc::new(LinuxSllDissector::new(sll2_id, true)));

    engine.register_table_entry(TableId::LinkType, LinkType::Ethernet.to_u32(), eth_id);
    engine.register_table_entry(TableId::LinkType, LinkType::Null.to_u32(), null_id);
    engine.register_table_entry(TableId::LinkType, LinkType::RawIp.to_u32(), raw_id);
    engine.register_table_entry(TableId::LinkType, LinkType::Ipv4.to_u32(), raw_id);
    engine.register_table_entry(TableId::LinkType, LinkType::Ipv6.to_u32(), raw_id);
    engine.register_table_entry(TableId::LinkType, LinkType::LinuxSll.to_u32(), sll_id);
    engine.register_table_entry(TableId::LinkType, LinkType::LinuxSll2.to_u32(), sll2_id);

    engine.register_table_entry(TableId::EtherType, 0x8100, vlan_id);
    engine.register_table_entry(TableId::EtherType, 0x88a8, vlan_id);

    // 2. Network & Tunneling layer
    let arp_id = ArpDissector::register(&mut engine.registry);
    let ipv4_id = Ipv4Dissector::register(&mut engine.registry);
    let ipv6_id = Ipv6Dissector::register(&mut engine.registry);
    let icmp_id = IcmpDissector::register(&mut engine.registry);
    let icmpv6_id = Icmpv6Dissector::register(&mut engine.registry);
    let igmp_id = IgmpDissector::register(&mut engine.registry);
    let gre_id = GreDissector::register(&mut engine.registry);
    let mpls_id = MplsDissector::register(&mut engine.registry);

    engine.register_dissector(Arc::new(ArpDissector::new(arp_id)));
    engine.register_dissector(Arc::new(Ipv4Dissector::new(ipv4_id)));
    engine.register_dissector(Arc::new(Ipv6Dissector::new(ipv6_id)));
    engine.register_dissector(Arc::new(IcmpDissector::new(icmp_id)));
    engine.register_dissector(Arc::new(Icmpv6Dissector::new(icmpv6_id)));
    engine.register_dissector(Arc::new(IgmpDissector::new(igmp_id)));
    engine.register_dissector(Arc::new(GreDissector::new(gre_id)));
    engine.register_dissector(Arc::new(MplsDissector::new(mpls_id)));

    engine.register_table_entry(TableId::EtherType, 0x0806, arp_id);
    engine.register_table_entry(TableId::EtherType, 0x8035, arp_id);
    engine.register_table_entry(TableId::EtherType, 0x0800, ipv4_id);
    engine.register_table_entry(TableId::EtherType, 0x86dd, ipv6_id);
    engine.register_table_entry(TableId::EtherType, 0x8847, mpls_id);
    engine.register_table_entry(TableId::EtherType, 0x8848, mpls_id);

    engine.register_table_entry(TableId::IpProto, 1, icmp_id);
    engine.register_table_entry(TableId::IpProto, 2, igmp_id);
    engine.register_table_entry(TableId::IpProto, 4, ipv4_id); // IP-in-IP
    engine.register_table_entry(TableId::IpProto, 41, ipv6_id); // IPv6-in-IPv4
    engine.register_table_entry(TableId::IpProto, 47, gre_id);
    engine.register_table_entry(TableId::IpProto, 58, icmpv6_id);

    // 3. Transport layer
    let tcp_id = TcpDissector::register(&mut engine.registry);
    let udp_id = UdpDissector::register(&mut engine.registry);
    let vxlan_id = VxlanDissector::register(&mut engine.registry);

    engine.register_dissector(Arc::new(TcpDissector::new(tcp_id)));
    engine.register_dissector(Arc::new(UdpDissector::new(udp_id)));
    engine.register_dissector(Arc::new(VxlanDissector::new(vxlan_id, eth_id)));

    engine.register_table_entry(TableId::IpProto, 6, tcp_id);
    engine.register_table_entry(TableId::IpProto, 17, udp_id);
    engine.register_table_entry(TableId::UdpPort, 4789, vxlan_id);

    // 4. Application layer
    let dns_id = DnsDissector::register(&mut engine.registry);
    let dhcp_id = DhcpDissector::register(&mut engine.registry);
    let http_id = HttpDissector::register(&mut engine.registry);
    let tls_id = TlsDissector::register(&mut engine.registry);
    let quic_id = QuicDissector::register(&mut engine.registry);
    let ntp_id = NtpDissector::register(&mut engine.registry);
    let ssh_id = TextProtocolDissector::register(
        &mut engine.registry,
        "Secure Shell Protocol",
        "SSH",
        "ssh",
        "ssh.protocol",
    );
    let ftp_id = TextProtocolDissector::register(
        &mut engine.registry,
        "File Transfer Protocol",
        "FTP",
        "ftp",
        "ftp.command",
    );
    let smtp_id = TextProtocolDissector::register(
        &mut engine.registry,
        "Simple Mail Transfer Protocol",
        "SMTP",
        "smtp",
        "smtp.command",
    );
    let syslog_id = TextProtocolDissector::register(
        &mut engine.registry,
        "Syslog Message",
        "Syslog",
        "syslog",
        "syslog.msg",
    );

    engine.register_dissector(Arc::new(DnsDissector::new(dns_id)));
    engine.register_dissector(Arc::new(DhcpDissector::new(dhcp_id)));
    engine.register_dissector(Arc::new(HttpDissector::new(http_id)));
    engine.register_dissector(Arc::new(TlsDissector::new(tls_id)));
    engine.register_dissector(Arc::new(QuicDissector::new(quic_id)));
    engine.register_dissector(Arc::new(NtpDissector::new(ntp_id)));
    engine.register_dissector(Arc::new(TextProtocolDissector::new(
        ssh_id,
        "SSH",
        "ssh.protocol",
    )));
    engine.register_dissector(Arc::new(TextProtocolDissector::new(
        ftp_id,
        "FTP",
        "ftp.command",
    )));
    engine.register_dissector(Arc::new(TextProtocolDissector::new(
        smtp_id,
        "SMTP",
        "smtp.command",
    )));
    engine.register_dissector(Arc::new(TextProtocolDissector::new(
        syslog_id,
        "Syslog",
        "syslog.msg",
    )));

    // Well-known UDP ports
    engine.register_table_entry(TableId::UdpPort, 53, dns_id);
    engine.register_table_entry(TableId::UdpPort, 5353, dns_id);
    engine.register_table_entry(TableId::UdpPort, 67, dhcp_id);
    engine.register_table_entry(TableId::UdpPort, 68, dhcp_id);
    engine.register_table_entry(TableId::UdpPort, 123, ntp_id);
    engine.register_table_entry(TableId::UdpPort, 443, quic_id);
    engine.register_table_entry(TableId::UdpPort, 514, syslog_id);

    // Well-known TCP ports
    engine.register_table_entry(TableId::TcpPort, 21, ftp_id);
    engine.register_table_entry(TableId::TcpPort, 22, ssh_id);
    engine.register_table_entry(TableId::TcpPort, 25, smtp_id);
    engine.register_table_entry(TableId::TcpPort, 587, smtp_id);
    engine.register_table_entry(TableId::TcpPort, 53, dns_id);
    engine.register_table_entry(TableId::TcpPort, 80, http_id);
    engine.register_table_entry(TableId::TcpPort, 8080, http_id);
    engine.register_table_entry(TableId::TcpPort, 8000, http_id);
    engine.register_table_entry(TableId::TcpPort, 443, tls_id);
    engine.register_table_entry(TableId::TcpPort, 8443, tls_id);

    // Heuristics for non-standard TCP ports
    engine.register_tcp_heuristic(http_id);
    engine.register_tcp_heuristic(tls_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mash_core::{ExpertGroup, Frame, NameResolver, ResolutionConfig, Timestamp};
    use mash_dissect::ConversationTracker;

    #[test]
    fn dissect_eth_ipv4_tcp_http_request() {
        let engine = build_default_engine();
        let mut resolver = NameResolver::new(ResolutionConfig::default());
        let mut conv = ConversationTracker::new();

        let http_payload = b"GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\nUser-Agent: mash-test\r\n\r\n";
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4 header (20 bytes)
        let ip_total = (20 + 20 + http_payload.len()) as u16;
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&ip_total.to_be_bytes());
        pkt.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, 6, 0x00, 0x00]);
        pkt.extend_from_slice(&[192, 168, 1, 10]);
        pkt.extend_from_slice(&[93, 184, 216, 34]);
        // TCP header (20 bytes)
        pkt.extend_from_slice(&54321u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&1000u32.to_be_bytes());
        pkt.extend_from_slice(&2000u32.to_be_bytes());
        pkt.extend_from_slice(&0x5018u16.to_be_bytes()); // hdr_len=20, PSH+ACK
        pkt.extend_from_slice(&65535u16.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(http_payload);

        let frame = Frame::new(1, Timestamp::from_secs_nanos(100, 0), LinkType::Ethernet, pkt);
        let dissected = engine.dissect_frame(&frame, None, None, &mut resolver, &mut conv);

        assert_eq!(dissected.summary.protocol, "HTTP");
        assert_eq!(dissected.summary.source, "192.168.1.10");
        assert_eq!(dissected.summary.destination, "93.184.216.34");
        assert_eq!(
            dissected.tree.protocols_in_frame,
            vec!["frame", "eth", "ip", "tcp", "http"]
        );
        assert_eq!(
            dissected
                .tree
                .by_abbrev("http.request.uri")
                .next()
                .unwrap()
                .value
                .as_str(),
            Some("/api/v1/status")
        );
        assert_eq!(
            dissected
                .tree
                .by_abbrev("http.host")
                .next()
                .unwrap()
                .value
                .as_str(),
            Some("example.com")
        );
    }

    #[test]
    fn dns_compression_pointer_loop_is_caught_without_hang_or_panic() {
        let engine = build_default_engine();
        let mut resolver = NameResolver::new(ResolutionConfig::default());
        let mut conv = ConversationTracker::new();

        // Construct Ethernet + IPv4 + UDP(53) + DNS query with a self-referencing pointer 0xc0 0x0c at offset 12
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4 (20)
        pkt.extend_from_slice(&[0x45, 0x00, 0x00, 44, 0, 1, 0, 0, 64, 17, 0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 1, 8, 8, 8, 8]);
        // UDP (8)
        pkt.extend_from_slice(&55555u16.to_be_bytes());
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(&24u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // DNS (16 bytes): txid=1, flags=0, qdcount=1, an=0, ns=0, ar=0, qname=0xc00c (points to itself!)
        pkt.extend_from_slice(&[
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01,
        ]);

        let frame = Frame::new(1, Timestamp::ZERO, LinkType::Ethernet, pkt);
        let dissected = engine.dissect_frame(&frame, None, None, &mut resolver, &mut conv);
        assert!(dissected
            .tree
            .experts
            .iter()
            .any(|e| e.group == ExpertGroup::Malformed));
    }
}

