# MUNG-ASH — Memory-Safe Network Protocol Analyzer & AI-Native Packet Suite

**MUNG-ASH** (`mash`) is a clean-room, 100% safe Rust (`#[forbid(unsafe_code)]`) network protocol analyzer, capture engine, and CLI/GUI/MCP suite with pluggable local and cloud AI assistants.

---

## Workspace Architecture (15 Crates)

| Crate | Responsibility |
|---|---|
| `crates/mash-core` | Core primitives (`Timestamp`, `LinkType`, `Frame`, `FieldTree`, `FieldNode`, `ByteRange`, `ExpertItem`, `NameResolver`, IEEE OUI & IANA service tables) |
| `crates/mash-pcapfile` | Classic libpcap (`µs`/`ns`, LE/BE) & PCAPNG (`SHB`, `IDB`, `EPB`, `SPB`, `NRB`, `ISB`, `DSB`) reader/writer, transparent `.gz`/`.lz4` compression, truncated-file recovery, and `text2pcap` engine |
| `crates/mash-dissect` | Dissector trait (`Dissector`), `Registry`, `PacketCursor` (bounds-checked slice reader), `DecodeAsTable`, `ConversationTracker`, and panic-guarded `DissectorEngine` |
| `crates/mash-protocols` | Clean-room Tier-1 & Tier-2 protocol dissectors written from public RFCs (`eth`, `vlan`, `null`, `raw`, `sll`, `arp`, `ip`, `ipv6`, `icmp`, `icmpv6`, `igmp`, `gre`, `mpls`, `tcp`, `udp`, `vxlan`, `dns`, `dhcp`, `http`, `tls`, `quic`, `ntp`, `ssh`, `ftp`, `smtp`, `syslog`) |
| `crates/mash-reassembly` | IPv4 datagram defragmentation, stateful TCP/UDP stream reassembly, Follow Stream formatting, and bomb-guarded HTTP gzip/deflate decompression |
| `crates/mash-filter` | Display Filter compiler, AST validator (with edit-distance `did_you_mean` suggestions), and fast evaluator (`==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `matches`, `in { ... }`, CIDR, slices, layer `#N`, `len`, `count`, `upper`, `lower`) |
| `crates/mash-crypto` | `SSLKEYLOGFILE` & pcapng `DSB` parser, RFC 8446 `HKDF-Expand-Label`, TLS 1.3 AEAD (`AES-128-GCM`, `AES-256-GCM`, `ChaCha20-Poly1305`) record decryption, and `zeroize`-backed secret memory scrubbing |
| `crates/mash-stats` | Capture file properties, Protocol Hierarchy (`io,phs`), Conversations (`conv,*`), Endpoints (`endpoints,*`), Packet Lengths (`plen`), Stateful TCP Sequence/RTT/Window Anomaly Analyzer, Expert Info summary, I/O Graph, and path-sanitized HTTP Object Exporter |
| `crates/mash-ai` | Pluggable `LlmProvider` trait, reversible `Redactor` (`IP_1`, `MAC_1`, `HOST_1.redacted`), `LocalOnly` privacy policy (`AIP-01`), prompt-injection XML sandboxing (`AIP-04`), audit trail, and NL-to-Display-Filter compiler |
| `crates/mash-mcp` | Model Context Protocol (MCP) JSON-RPC 2.0 server (`mash-mcp`) exposing 6 structured packet analysis tools |
| `crates/mash-plugin` | Declarative custom protocol dissector plugin loader and sandboxed runtime |
| `crates/mash-capture` | Interface enumeration and ring-buffer file rotation coordinator |
| `crates/mash-cap` | Minimal isolated packet capture helper binary (`mash-cap`) with zero dissector/filter/AI dependencies |
| `crates/mash-cli` | Complete CLI suite (`mash`, `mash-info`, `mash-edit`, `mash-merge`, `mash-text2pcap`) |
| `crates/mash-gui` | Three-pane synchronized analyzer workspace (`mash-gui`) with virtualized packet list, bidirectional field-to-byte highlighting, coloring rules, and profiles |

