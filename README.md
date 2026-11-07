# MUNG-ASH — Memory-Safe Network Protocol Analyzer & AI-Native Packet Suite

**MUNG-ASH** (`mash`) is a clean-room, 100% safe Rust (`#[forbid(unsafe_code)]`) network protocol analyzer, capture engine, and CLI/GUI/MCP suite with pluggable local and cloud AI assistants.

---

## Workspace Architecture (15 Crates)

| Crate | Responsibility |
|---|---|
| `crates/mash-core` | Core primitives (`Timestamp`, `LinkType`, `Frame`, `FieldTree`, `FieldNode`, `ByteRange`, `ExpertItem`, `NameResolver`, IEEE OUI & IANA service tables) |
| `crates/mash-pcapfile` | Classic libpcap (`µs`/`ns`, LE/BE) & PCAPNG (`SHB`, `IDB`, `EPB`, `SPB`, `NRB`, `ISB`, `DSB`) reader/writer, transparent `.gz`/`.lz4` compression, truncated-file recovery, and `text2pcap` engine |
| `crates/mash-dissect` | Dissector trait (`Dissector`), `Registry`, `PacketCursor` (bounds-checked slice reader), `DecodeAsTable`, `ConversationTracker`, and panic-guarded `DissectorEngine` |
| `crates/mash-protocols` | 33 clean-room protocol dissectors written from public RFCs (`eth`, `vlan`, `null`, `raw`, `sll`, `sll2`, `arp`, `ip`, `ipv6`, `icmp`, `icmpv6`, `igmp`, `gre`, `mpls`, `ospf`, `tcp`, `udp`, `vxlan`, `dns`, `dhcp`, `dhcpv6`, `http`, `tls`, `quic`, `ntp`, `ssh`, `ftp`, `smtp`, `syslog`, `bgp`, `smb2`, `grpc`, `mqtt`, `modbus`) |
| `crates/mash-reassembly` | IPv4 datagram defragmentation, stateful TCP/UDP stream reassembly, Follow Stream formatting, and bomb-guarded HTTP gzip/deflate decompression |
| `crates/mash-filter` | Display Filter compiler, AST validator (with edit-distance `did_you_mean` suggestions), and fast evaluator (`==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `matches`, `in { ... }`, CIDR, slices, layer `#N`, `len`, `count`, `upper`, `lower`) |
| `crates/mash-crypto` | `SSLKEYLOGFILE` & pcapng `DSB` parser, RFC 8446 `HKDF-Expand-Label` & RFC 5246 TLS 1.2 PRF, stateful TLS 1.2/1.3 AEAD (`AES-128-GCM`, `AES-256-GCM`, `ChaCha20-Poly1305`) record decryptor, HMAC-keyed `PcapAnonymizer`, and `zeroize`-backed secret memory scrubbing |
| `crates/mash-stats` | Capture file properties, Protocol Hierarchy (`io,phs`), Conversations (`conv,*`), Endpoints (`endpoints,*`), Packet Lengths (`plen`), Stateful TCP Sequence/RTT/Window Anomaly Analyzer, Expert Info summary, I/O Graph, and path-sanitized HTTP Object Exporter |
| `crates/mash-ai` | Pluggable `LlmProvider` trait, reversible `Redactor` (`IP_1`, `MAC_1`, `HOST_1.redacted`), `LocalOnly` privacy policy (`AIP-01`), prompt-injection XML sandboxing (`AIP-04`), audit trail, and NL-to-Display-Filter compiler |
| `crates/mash-mcp` | Model Context Protocol (MCP) JSON-RPC 2.0 server (`mash-mcp`) exposing 6 structured packet analysis tools |
| `crates/mash-plugin` | Declarative custom protocol dissector plugin loader and sandboxed runtime |
| `crates/mash-capture` | Host OS interface discovery, safe BPF capture filter compiler (`BpfFilter`), live UDP/probe capture engine, and ring-buffer file rotation coordinator |
| `crates/mash-cap` | Minimal isolated packet capture helper binary (`mash-cap`) with zero dissector/filter/AI dependencies |
| `crates/mash-cli` | Complete CLI & 3-pane TUI suite (`mash`, `mash --gui`, `mash --tui`, `mash-info`, `mash-edit`, `mash-merge`, `mash-text2pcap`) |
| `crates/mash-gui` | Native 3-pane Desktop GUI (`mash-gui`, powered by `eframe`/`egui`) unifying all 8 MUNG-ASH tools in one application |

---

## All-in-One Desktop GUI (`mung-ash.exe` / `mash-gui` / `mash --gui`)

Launch the native desktop graphical interface with:

```powershell
mung-ash
# or
mash-gui
# or
mash --gui
```

The GUI provides a classic layout with all 8 MUNG-ASH tools built directly into the top toolbar and menu bar:
- **Top Menu & Toolbar**: Quick access to **Live Capture (`mash-cap`)**, **Demo Multi-Protocol Showcase Capture**, **File Open/Save**, **Capture Properties (`mash-info`)**, **Packet Editor & HMAC Anonymizer (`mash-edit`)**, **Capture Merger (`mash-merge`)**, **Hex2Pcap Importer (`mash-text2pcap`)**, **Follow TCP/UDP Stream**, **Protocol Hierarchy & Conversation Statistics**, **AI Security Analyst (`mash-ai`)**, and **MCP JSON-RPC 2.0 Console (`mash-mcp`)**.
- **Live Display Filter Bar**: Instant green/red syntax validation, edit-distance `Did you mean ...?` auto-fix buttons, and one-click protocol filter presets.
- **Synchronized 3-Pane Workspace**:
  - **Pane 1 (Packet List)**: Resizable, striped table (`No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`) with color rules and right-click context menu (`Mark`, `Time Reference`, `Follow Stream`, `Explain with AI`).
  - **Pane 2 (Protocol Details Tree)**: Expandable protocol hierarchy with Expert Info severity badges, right-click `Apply as Filter` / `Copy`, and click-to-highlight bytes in Pane 3.
  - **Pane 3 (Packet Bytes — Hex + ASCII)**: 16-byte aligned Hex + ASCII view with secondary Data Source tabs and click-any-byte to jump directly to the owning field in Pane 2.

---

## Installation

### Windows (PowerShell)

Run the included installer script from the repository root to build all 8 release binaries and install them into `~/.cargo/bin` (on your `PATH`):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

To also create a portable `.zip` release bundle in `dist\`:
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -CreateZip
```

To uninstall:
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
```

### Linux & macOS

```sh
chmod +x ./install.sh
./install.sh
# Optional on Linux: grant packet capture capabilities to mash-cap
./install.sh --setcap
```

---

## Installed Binaries (8 Tools)

| Binary | Role | Example Command |
|---|---|---|
| `mash` | Primary CLI & 3-pane Terminal UI analyzer | `mash -r capture.pcapng -Y "tcp.port == 443"` or `mash --tui -r capture.pcapng` |
| `mash-gui` | Desktop 3-pane graphical protocol analyzer | `mash-gui capture.pcapng` |
| `mash-cap` | Minimal isolated packet capture helper | `mash-cap -i eth0 -f "udp and port 53" -c 100 -w dns.pcapng` |
| `mash-info` | Capture metadata, timing & SHA-256 inspector | `mash-info capture.pcapng` |
| `mash-edit` | Packet slicer, deduplicator & HMAC anonymizer | `mash-edit -d --anonymize my-secret-key in.pcapng out.pcapng` |
| `mash-merge` | Chronological / concatenated multi-file merger | `mash-merge -w merged.pcapng part1.pcapng part2.pcapng` |
| `mash-text2pcap` | ASCII hex dump to PCAP/PCAPNG converter | `mash-text2pcap -T 54321,80 dump.txt http.pcapng` |
| `mash-mcp` | Model Context Protocol (MCP) JSON-RPC 2.0 server | `mash-mcp` |

