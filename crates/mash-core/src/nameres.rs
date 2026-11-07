use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Name resolution settings (whether to resolve MACs, network addresses, and transport ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionConfig {
    pub resolve_mac: bool,
    pub resolve_network: bool,
    pub resolve_transport: bool,
    pub use_captured_dns: bool,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            resolve_mac: true,
            resolve_network: false,
            resolve_transport: false,
            use_captured_dns: true,
        }
    }
}

impl ResolutionConfig {
    pub fn disabled() -> Self {
        Self {
            resolve_mac: false,
            resolve_network: false,
            resolve_transport: false,
            use_captured_dns: false,
        }
    }
}

/// Bundled and user-extensible database for OUI MAC vendors, IP hosts, and TCP/UDP services.
#[derive(Debug, Clone, Default)]
pub struct NameResolver {
    pub config: ResolutionConfig,
    custom_hosts_v4: HashMap<[u8; 4], String>,
    custom_hosts_v6: HashMap<[u8; 16], String>,
    learned_dns_v4: HashMap<[u8; 4], String>,
    learned_dns_v6: HashMap<[u8; 16], String>,
    custom_ethers: HashMap<[u8; 6], String>,
    custom_tcp_services: HashMap<u16, String>,
    custom_udp_services: HashMap<u16, String>,
}

impl NameResolver {
    pub fn new(config: ResolutionConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn add_host_v4(&mut self, ip: [u8; 4], name: impl Into<String>) {
        self.custom_hosts_v4.insert(ip, name.into());
    }

    pub fn add_host_v6(&mut self, ip: [u8; 16], name: impl Into<String>) {
        self.custom_hosts_v6.insert(ip, name.into());
    }

    pub fn learn_dns_v4(&mut self, ip: [u8; 4], name: impl Into<String>) {
        self.learned_dns_v4.insert(ip, name.into());
    }

    pub fn learn_dns_v6(&mut self, ip: [u8; 16], name: impl Into<String>) {
        self.learned_dns_v6.insert(ip, name.into());
    }

    pub fn add_ether(&mut self, mac: [u8; 6], name: impl Into<String>) {
        self.custom_ethers.insert(mac, name.into());
    }

    pub fn add_tcp_service(&mut self, port: u16, name: impl Into<String>) {
        self.custom_tcp_services.insert(port, name.into());
    }

    pub fn add_udp_service(&mut self, port: u16, name: impl Into<String>) {
        self.custom_udp_services.insert(port, name.into());
    }

    /// Parse a standard `hosts` file string and load IPv4 entries.
    pub fn load_hosts_str(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(ip_str), Some(host)) = (parts.next(), parts.next()) {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    self.add_host_v4(ip.octets(), host);
                } else if let Ok(ip6) = ip_str.parse::<std::net::Ipv6Addr>() {
                    self.add_host_v6(ip6.octets(), host);
                }
            }
        }
    }

    pub fn format_mac(&self, mac: [u8; 6]) -> String {
        if mac == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] && self.config.resolve_mac {
            return "Broadcast".to_string();
        }
        if self.config.resolve_mac {
            if let Some(name) = self.custom_ethers.get(&mac) {
                return name.clone();
            }
            let oui = [mac[0], mac[1], mac[2]];
            if let Some(vendor) = lookup_oui(oui) {
                return format!("{vendor}_{:02x}:{:02x}:{:02x}", mac[3], mac[4], mac[5]);
            }
        }
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    pub fn format_ipv4(&self, ip: [u8; 4]) -> String {
        if self.config.resolve_network {
            if let Some(h) = self.custom_hosts_v4.get(&ip) {
                return h.clone();
            }
            if self.config.use_captured_dns {
                if let Some(h) = self.learned_dns_v4.get(&ip) {
                    return h.clone();
                }
            }
        }
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }

    pub fn format_ipv6(&self, ip: [u8; 16]) -> String {
        if self.config.resolve_network {
            if let Some(h) = self.custom_hosts_v6.get(&ip) {
                return h.clone();
            }
            if self.config.use_captured_dns {
                if let Some(h) = self.learned_dns_v6.get(&ip) {
                    return h.clone();
                }
            }
        }
        std::net::Ipv6Addr::from(ip).to_string()
    }

    pub fn tcp_service_name(&self, port: u16) -> Option<&str> {
        if let Some(s) = self.custom_tcp_services.get(&port) {
            return Some(s.as_str());
        }
        lookup_well_known_port(port, true)
    }

    pub fn udp_service_name(&self, port: u16) -> Option<&str> {
        if let Some(s) = self.custom_udp_services.get(&port) {
            return Some(s.as_str());
        }
        lookup_well_known_port(port, false)
    }

    pub fn format_tcp_port(&self, port: u16) -> String {
        if self.config.resolve_transport {
            if let Some(s) = self.tcp_service_name(port) {
                return format!("{s} ({port})");
            }
        }
        port.to_string()
    }

    pub fn format_udp_port(&self, port: u16) -> String {
        if self.config.resolve_transport {
            if let Some(s) = self.udp_service_name(port) {
                return format!("{s} ({port})");
            }
        }
        port.to_string()
    }
}

/// Bundled OUI prefix lookup from public IEEE registration data.
pub fn lookup_oui(oui: [u8; 3]) -> Option<&'static str> {
    match oui {
        [0x00, 0x00, 0x0c] | [0x00, 0x01, 0x42] | [0x00, 0x1b, 0x0d] => Some("Cisco"),
        [0x00, 0x05, 0x69] | [0x00, 0x0c, 0x29] | [0x00, 0x50, 0x56] => Some("VMware"),
        [0x08, 0x00, 0x27] | [0x0a, 0x00, 0x27] => Some("VBox"),
        [0x52, 0x54, 0x00] => Some("QEMU"),
        [0x00, 0x15, 0x5d] => Some("Microsoft"),
        [0x00, 0x16, 0x3e] => Some("Xen"),
        [0x02, 0x42, 0xac] => Some("Docker"),
        [0x00, 0x1a, 0x11] | [0x3c, 0x5a, 0xb4] | [0xf4, 0xf5, 0xd8] => Some("Google"),
        [0x00, 0x03, 0x93] | [0x00, 0x17, 0xf2] | [0x3c, 0x06, 0x30] | [0xa4, 0x83, 0xe7] => Some("Apple"),
        [0x00, 0x1b, 0x21] | [0x3c, 0xfd, 0xfe] | [0x68, 0x05, 0xca] => Some("Intel"),
        [0xb8, 0x27, 0xeb] | [0xdc, 0xa6, 0x32] | [0xe4, 0x5f, 0x01] => Some("RaspberryPi"),
        [0x00, 0x00, 0x5e] => Some("IANA-VRRP"),
        [0x01, 0x00, 0x5e] => Some("IPv4mcast"),
        [0x33, 0x33, _] => Some("IPv6mcast"),
        _ => None,
    }
}

/// Well-known IANA TCP/UDP service names.
pub fn lookup_well_known_port(port: u16, is_tcp: bool) -> Option<&'static str> {
    match (port, is_tcp) {
        (7, _) => Some("echo"),
        (20, true) => Some("ftp-data"),
        (21, true) => Some("ftp"),
        (22, _) => Some("ssh"),
        (23, true) => Some("telnet"),
        (25, true) => Some("smtp"),
        (53, _) => Some("domain"),
        (67, false) => Some("bootps"),
        (68, false) => Some("bootpc"),
        (69, false) => Some("tftp"),
        (80, _) => Some("http"),
        (88, _) => Some("kerberos"),
        (110, true) => Some("pop3"),
        (123, false) => Some("ntp"),
        (137, _) => Some("netbios-ns"),
        (138, _) => Some("netbios-dgm"),
        (139, true) => Some("netbios-ssn"),
        (143, true) => Some("imap"),
        (161, false) => Some("snmp"),
        (162, false) => Some("snmptrap"),
        (179, true) => Some("bgp"),
        (389, _) => Some("ldap"),
        (443, true) => Some("https"),
        (443, false) => Some("quic"),
        (445, true) => Some("microsoft-ds"),
        (465, true) => Some("smtps"),
        (500, false) => Some("isakmp"),
        (502, true) => Some("modbus"),
        (514, false) => Some("syslog"),
        (546, false) => Some("dhcpv6-client"),
        (547, false) => Some("dhcpv6-server"),
        (587, true) => Some("submission"),
        (636, true) => Some("ldaps"),
        (853, _) => Some("domain-s"),
        (993, true) => Some("imaps"),
        (995, true) => Some("pop3s"),
        (1812, false) => Some("radius"),
        (1813, false) => Some("radius-acct"),
        (1883, true) => Some("mqtt"),
        (2049, _) => Some("nfs"),
        (3306, true) => Some("mysql"),
        (3389, _) => Some("ms-wbt-server"),
        (4500, false) => Some("ipsec-nat-t"),
        (4789, false) => Some("vxlan"),
        (5060, _) => Some("sip"),
        (5061, true) => Some("sips"),
        (5353, false) => Some("mdns"),
        (5432, true) => Some("postgresql"),
        (6081, false) => Some("geneve"),
        (6379, true) => Some("redis"),
        (8080, _) => Some("http-alt"),
        (8443, _) => Some("https-alt"),
        (8883, true) => Some("secure-mqtt"),
        _ => None,
    }
}

/// Standard IANA IP protocol numbers.
pub fn ip_protocol_name(proto: u8) -> &'static str {
    match proto {
        0 => "HOPOPT",
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPv4",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        43 => "IPv6-Route",
        44 => "IPv6-Frag",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        59 => "IPv6-NoNxt",
        60 => "IPv6-Opts",
        89 => "OSPF",
        112 => "VRRP",
        132 => "SCTP",
        _ => "Unknown",
    }
}
