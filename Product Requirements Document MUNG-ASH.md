### you are strictly forbidden from porting or consulting Wireshark's GPL-licensed C source code. Every protocol dissector must be written from scratch using public RFCs, specifications, or reverse-engineering sample captures.

# Product Requirements Document: MUNG-ASH

**A Rust network protocol analyzer with Wireshark-level capability and pluggable AI assistants**

**Version:** 1.0 (Draft) · **Product name:** MUNG-ASH (Wireshark is a registered trademark, so the name and branding must not imply affiliation) · **Language:** Rust (stable toolchain)

## 1. Executive Summary

MUNG-ASH is a memory-safe, cross-platform network protocol analyzer written in Rust. It captures live traffic, reads and writes standard capture files, dissects protocols into an inspectable field tree, and lets users filter, search, reassemble, decrypt, and statistically analyze traffic through a desktop GUI and a family of command-line tools.

The goal is functional parity with Wireshark (GUI) and its companion tools (TShark, dumpcap, editcap, mergecap, capinfos, text2pcap), plus the improvements Rust makes practical: memory safety in untrusted-input parsers, parallel dissection, an embeddable library, and an optional AI layer that works with local models, Google Gemini, and Claude.

**On “exactly what Wireshark does.”** Wireshark represents 25+ years of work and several thousand protocol dissectors, so literal day-one parity is not achievable. Section 4 defines parity in measurable tiers. Each tier is a shippable product, and parity is tracked by an automated differential test against TShark.

## 2. Problem and Opportunity

- Dissectors parse hostile input and are mostly written in C; they have historically been a frequent source of security advisories. Rust removes most memory-corruption bug classes by construction.
- Large captures (multi-GB) are slow to open and memory-hungry in single-threaded designs. A parallel, indexed design can improve this substantially.
- Wireshark’s engine is hard to embed. A clean Rust library lets IDS, CI, observability, and test tooling reuse the same dissectors.
- A single static binary with few runtime dependencies simplifies use on jump boxes, containers, and embedded Linux.

## 3. Goals and Non-Goals

**Goals**

- G1. Live capture on Windows, Linux, and macOS with capture filters and ring-buffer output.
- G2. Read and write pcap and pcapng with full metadata fidelity.
- G3. Dissect protocols into a hierarchical, typed field tree with byte-level highlighting.
- G4. A display filter language compatible with Wireshark’s syntax for the common subset.
- G5. A responsive GUI and scriptable CLI covering the main Wireshark and TShark workflows.
- G6. Safe on hostile input: no panics, no undefined behavior, bounded resources.
- G7. All functionality exposed as reusable library crates.
- G8. A provider-agnostic AI layer that works with local models and with hosted models from Google and Anthropic, switchable per profile (Section 6.13).

**Non-goals (v1)**

- Not an IDS/IPS or long-term network monitoring platform.
- Not a packet crafting or injection framework (text2pcap-style import only).
- No hosted or cloud capture service.
- No compatibility with Wireshark’s C plugin ABI; Lua compatibility is a later, partial layer.
- No promise of the full Wireshark protocol list at v1.0.
- No AI in the capture, dissection, or filtering path, and no autonomous AI actions: LLMs suggest and explain, and the user confirms anything that changes state.
- No AI service run by the project and no dependence on a single LLM vendor: users bring a local model or their own API key.

## 4. Parity Definition and Protocol Tiers

Parity is measured by (a) protocol coverage, (b) field-name and field-value agreement with TShark on a reference corpus, and (c) the feature checklist in Section 6.

- **Tier 1 (MVP):** Ethernet, Linux cooked (SLL/SLL2), loopback/null, raw IP, 802.1Q/QinQ, ARP, IPv4, IPv6 with extension headers, ICMP, ICMPv6/NDP, IGMP, TCP, UDP, DNS, mDNS, DHCP, DHCPv6, HTTP/1.x, TLS 1.2/1.3 (records and handshake), SSH (banner and key exchange), FTP, SMTP, NTP, Syslog.
- **Tier 2 (v1.0):** HTTP/2, QUIC and HTTP/3, WebSocket, MQTT, SMB2/3, LDAP, Kerberos, SIP/SDP, RTP/RTCP, BGP, OSPF, VRRP, STP, LLDP, CDP, GRE, VXLAN, GENEVE, MPLS, IPsec ESP/AH, IKEv2, SNMP, RADIUS, TFTP, POP3/IMAP, NFS, RDP, SCTP, Modbus/TCP.
- **Tier 3 (v1.x–2.0):** IEEE 802.11 with WPA2/WPA3 decryption, Bluetooth HCI/L2CAP, USB, CAN, Zigbee, Diameter, GTP, 5G NAS/NGAP, SS7, industrial and automotive protocols, and the long tail via plugins.

## 5. Target Users

- **Network engineer:** troubleshoots latency, retransmissions, DNS/DHCP faults, routing issues; relies on I/O graphs, TCP analysis, and conversation statistics.
- **Security analyst / incident responder:** triages PCAPs, follows streams, decrypts TLS with key logs, extracts objects, exports indicators.
- **Developer / QA engineer:** debugs protocol implementations, compares traces, automates checks in CI through the CLI and library.
- **Student / educator:** learns protocols through readable field trees and sample captures.
- **Tool integrator:** embeds dissection in another Rust application.

## 6. Functional Requirements

Priority: **P0** = required for MVP, **P1** = required for v1.0, **P2** = after 1.0.

### 6.1 Live Capture

- **CAP-01 (P0):** Enumerate interfaces with name, description, addresses, link type, and status, including pseudo-interfaces (any, loopback) where supported.
- **CAP-02 (P0):** Capture via libpcap (Linux/macOS) and Npcap (Windows); native AF\_PACKET (TPACKET\_V3, memory-mapped) backend on Linux for high rates.
- **CAP-03 (P0):** BPF capture filters with syntax validation before start.
- **CAP-04 (P0):** Snaplen, promiscuous mode, buffer size, and timestamp precision/source options.
- **CAP-05 (P1):** Multiple simultaneous interfaces with per-interface metadata in pcapng.
- **CAP-06 (P1):** Ring-buffer capture with rotation by size, duration, or packet count; auto-stop conditions.
- **CAP-07 (P1):** Remote capture over SSH, and capture from named pipes and stdin.
- **CAP-08 (P1):** Monitor mode and radiotap capture for Wi-Fi where the OS supports it.
- **CAP-09 (P1):** Privilege separation: capture runs in a minimal helper process (mash-cap); the GUI and dissectors never run elevated.
- **CAP-10 (P2):** Hardware timestamps, drop counters, and kernel-bypass backends (AF\_XDP).

### 6.2 Capture File Formats

- **FIL-01 (P0):** Read and write pcap (micro- and nanosecond) and pcapng (SHB, IDB, EPB, SPB, NRB, ISB, DSB, custom blocks, packet comments).
- **FIL-02 (P0):** Transparent compression: gzip, zstd, and LZ4 read; gzip and zstd write.
- **FIL-03 (P1):** Read common third-party formats: Snoop, NetMon, Sniffer, Endace ERF, K12 text, and others on a best-effort basis.
- **FIL-04 (P0):** Memory-mapped and streaming readers that handle files larger than RAM.
- **FIL-05 (P1):** Save subsets (displayed, marked, ranges); merge, split, and trim (mergecap and editcap equivalents).
- **FIL-06 (P1):** Import hex dumps (text2pcap equivalent) with synthetic headers.
- **FIL-07 (P0):** Corrupt or truncated files open as far as possible with a clear warning, never a crash.

### 6.3 Dissection Engine

- **DIS-01 (P0):** Layered dissection from link type upward, driven by dissector tables keyed by Ethertype, IP protocol, TCP/UDP port, content type, ALPN, and so on.
- **DIS-02 (P0):** Heuristic dissectors for non-standard ports, with user override (Decode As).
- **DIS-03 (P0):** Output is a typed field tree: each field has an abbreviation (for example tcp.srcport), type, display text, byte range, bit mask, and expert flags.
- **DIS-04 (P0):** Zero-copy parsing over borrowed byte slices; no per-field heap allocation on the hot path.
- **DIS-05 (P0):** Malformed input yields a partial tree plus a structured error; dissectors never panic and use bounded recursion and allocation.
- **DIS-06 (P1):** Two-pass dissection so later packets can inform earlier ones (request/response matching, TCP analysis).
- **DIS-07 (P1):** Bidirectional conversation tracking with per-conversation state slots that dissectors can attach to.
- **DIS-08 (P1):** Tunnel recursion with depth limits (GRE, VXLAN, IP-in-IP, GTP, IPsec).
- **DIS-09 (P1):** Field types: integers (bitfields, enums, flags), floats, MAC, IPv4/IPv6, strings (ASCII, UTF-8, UTF-16), OIDs, absolute and relative time, byte arrays, and sub-trees.
- **DIS-10 (P2):** A declarative protocol definition language that compiles to dissectors.

### 6.4 Reassembly

- **REA-01 (P0):** IPv4/IPv6 fragment reassembly with overlap policy and timeouts.
- **REA-02 (P0):** TCP stream reassembly handling out-of-order, retransmission, overlap, missing segments, window scaling, SACK, and keep-alives.
- **REA-03 (P1):** Application-layer reassembly across segments (HTTP bodies, TLS records, SMB, DNS over TCP).
- **REA-04 (P1):** Decompression (gzip, deflate, brotli) of HTTP content and extraction of transferred objects.
- **REA-05 (P1):** Bounded memory per stream and globally, with a visible indicator when truncation occurs.

### 6.5 Display Filters

- **FLT-01 (P0):** Field references; comparison operators (==, !=, >, <, >=, <=); logical operators (&&, ||, !, and, or, not); sets and ranges; slices; contains; matches (regex); CIDR masks.
- **FLT-02 (P0):** Compile filters once to bytecode or a closure tree; evaluate with no allocation per packet.
- **FLT-03 (P0):** Live syntax check with error position and suggestions; field-name and value auto-complete in the GUI.
- **FLT-04 (P1):** Functions (len, count, upper, lower, string), field layers (tcp.port#2), arithmetic, saved filters, macros, and filter buttons.
- **FLT-05 (P1):** At least 95% of the filters in Wireshark’s documented examples and a curated set of 500 popular community filters behave identically on the reference corpus.
- **FLT-06 (P1):** Filter expression builder, plus Apply as Filter, Prepare as Filter, and Conversation Filter from any field.

### 6.6 Graphical User Interface

- **GUI-01 (P0):** Three-pane main window: packet list, packet details (collapsible field tree), packet bytes (hex and ASCII), with linked selection and byte highlighting.
- **GUI-02 (P0):** Virtualized packet list that stays responsive with 10+ million packets; configurable columns, including custom field columns.
- **GUI-03 (P0):** Coloring rules (default set plus user-defined, filter-driven) with import and export.
- **GUI-04 (P0):** Find packet (by filter, hex, string, regex), go to packet, next/previous in conversation, mark, ignore, comment, time reference, and time display formats.
- **GUI-05 (P1):** Follow TCP, UDP, TLS, HTTP, HTTP/2, and QUIC streams with ASCII, hex, raw, and YAML views, per-direction coloring, and export.
- **GUI-06 (P1):** Multiple byte views for derived data (reassembled, decrypted, decompressed).
- **GUI-07 (P1):** All statistics windows from 6.8, and an I/O graph with multiple filtered series and export.
- **GUI-08 (P1):** Capture dialogs: interface list with live sparklines, options, filters, and ring-buffer settings.
- **GUI-09 (P1):** Profiles, dark and light themes, HiDPI, keyboard-first operation, and accessibility (screen-reader roles, contrast, keyboard navigation).
- **GUI-10 (P1):** Localization with right-to-left layout support.
- **GUI-11 (P2):** Side-by-side comparison of two captures.

### 6.7 Command-Line Tools

Binaries: `mash` (TShark equivalent), `mash-cap` (dumpcap), `mash-edit` (editcap), `mash-merge` (mergecap), `mash-info` (capinfos), `mash-text2pcap`, and `mash-mcp` (MCP server for AI clients, see 6.13).

- **CLI-01 (P0):** Read from file or live interface; write to file; options equivalent to -r, -w, -i, -f, -Y, -c, -a, and -n.
- **CLI-02 (P0):** Output formats: summary text, verbose tree, JSON, JSON Lines (streaming), CSV via field selection (-T fields -e), PDML- and PSML-style XML.
- **CLI-03 (P0):** Scriptable exit codes and stderr messages; deterministic output suitable for diffing.
- **CLI-04 (P1):** Two-pass analysis, statistics (-z) for everything in 6.8, and object export.
- **CLI-05 (P1):** Same short flags as TShark for its 40 most common options.
- **CLI-06 (P1):** Shell completion and man pages.

### 6.8 Analysis and Statistics

- **STA-01 (P0):** Capture file properties, protocol hierarchy, conversations and endpoints (Ethernet, IPv4/6, TCP, UDP), and packet length distribution.
- **STA-02 (P1):** TCP analysis flags (retransmission, fast retransmission, duplicate ACK, out-of-order, zero window, window update, keep-alive, lost segment, spurious retransmission), RTT and bytes in flight, and TCP stream graphs (time-sequence, throughput, RTT, window scaling).
- **STA-03 (P1):** Flow graph (sequence diagram), HTTP, DNS, SIP, and SMB statistics, and request/response times.
- **STA-04 (P1):** VoIP analysis: SIP call list, RTP stream analysis (jitter, loss, MOS estimate), and RTP playback.
- **STA-05 (P1):** Expert Information with severity levels (Error, Warning, Note, Chat), grouping, a summary window, and filterability through the display filter language.
- **STA-06 (P1):** Export objects (HTTP, SMB, TFTP, IMF) with safe filename handling.
- **STA-07 (P2):** GeoIP and ASN enrichment from user-supplied databases, with map views.

### 6.9 Decryption

- **DEC-01 (P0):** TLS 1.2/1.3 decryption via SSLKEYLOGFILE and secrets embedded in pcapng (DSB).
- **DEC-02 (P1):** TLS decryption with an RSA private key for non-forward-secret cipher suites.
- **DEC-03 (P1):** WPA/WPA2/WPA3-Personal decryption from a PSK or passphrase and SSID, with 802.11 handshake detection.
- **DEC-04 (P1):** IPsec ESP and IKEv2 decryption from supplied SA keys; Kerberos with a keytab; SSH where keys are supplied.
- **DEC-05 (P1):** Audited cryptographic crates only; secrets zeroized in memory; keys never written to disk by default.

### 6.10 Name Resolution

- **RES-01 (P0):** MAC vendor (OUI), service/port, and protocol names from a bundled database.
- **RES-02 (P1):** Optional reverse DNS (asynchronous, cached, off by default), plus names learned from DNS responses inside the capture.
- **RES-03 (P1):** User-editable hosts, ethers, and services files, with per-profile settings.

### 6.11 Extensibility

- **EXT-01 (P1):** Stable, versioned Rust library API with semver guarantees after 1.0.
- **EXT-02 (P1):** WebAssembly plugin system (WASI components) for sandboxed dissectors and taps, with capability-based permissions.
- **EXT-03 (P2):** Lua compatibility layer for the most-used Wireshark Lua APIs (Proto, ProtoField, DissectorTable, Tap) and Python bindings for the library.
- **EXT-04 (P2):** Plugin manager with signature verification.

### 6.12 Configuration and Profiles

- **CFG-01 (P0):** Documented TOML configuration in OS-appropriate directories, plus a portable mode.
- **CFG-02 (P1):** Profiles bundling columns, filters, coloring rules, layout, preferences, and Decode As rules; switchable at runtime and from the CLI.
- **CFG-03 (P1):** Recovery of unsaved captures after a crash.

### 6.13 AI Assistant and LLM Integration

MUNG-ASH treats LLMs as interchangeable, optional back ends behind one provider interface. The same features work with a local model on the analyst’s own machine, Google Gemini, or Claude, and users switch providers per profile without changing their workflow. The AI layer sits behind an `ai` feature flag, is off by default, and never runs inside the capture, dissection, or filter path.

**Providers and configuration**

- **AI-01 (P1):** One `LlmProvider` trait (chat, streaming, tool calling, structured JSON output, model listing, token counting) with adapters for: local runtimes (Ollama, llama.cpp server, LM Studio, vLLM, any OpenAI-compatible endpoint); Google (Gemini API and Vertex AI); Anthropic (Claude API, plus Claude through Amazon Bedrock and Google Vertex AI); and other OpenAI-compatible hosted services.
- **AI-02 (P1):** Provider profiles store endpoint, model, parameters, timeout, and a capability record (context window, tool use, vision, JSON mode). When a model lacks a capability, features degrade gracefully, for example from native tool calling to prompted JSON.
- **AI-03 (P1):** API keys live in the OS keychain (or environment variables in the CLI) and are never written to config files, logs, or capture files.
- **AI-04 (P1):** User-defined routing and fallback (for example local first, cloud on request), retries with backoff, and an optional per-session token and cost budget with a visible counter.
- **AI-05 (P2):** Optional in-process local inference (llama.cpp bindings or candle) so a fully offline install needs no separate server.

**Assistant features (all optional, read-only by default)**

- **AI-10 (P1):** Explain this: a plain-language explanation of the selected packet, field, expert item, or stream, grounded in the dissected field tree. Available from the context menu and an assistant side panel that shows the active provider and a local-only indicator.
- **AI-11 (P1):** Natural language to display filter. The model proposes a filter, the `mash-filter` compiler validates it, and invalid output is repaired or rejected. The result is shown for review and applied on the user’s click.
- **AI-12 (P1):** Capture summary: top talkers, protocol mix, TCP and expert findings, and anomalies, generated from computed statistics (STA-01 to STA-05) rather than raw packets.
- **AI-13 (P2):** Investigation chat that can call read-only tools (run a filter, list conversations, follow a stream, fetch statistics); every tool call and result is visible to the user.
- **AI-14 (P2):** Draft an incident or troubleshooting report in Markdown from selected packets and findings, citing packet numbers for each claim.
- **AI-15 (P2):** Dissector scaffolding: draft a dissector or DSL definition from a protocol description or sample capture. The output is code for human review and passes the normal test and fuzz gates.

**MCP server mode**

- **MCP-01 (P1):** `mash-mcp` exposes MUNG-ASH as a Model Context Protocol server (stdio and local HTTP), so any MCP-capable client (Claude, IDE agents, local-model front ends) can open captures, apply filters, fetch statistics, and follow streams.
- **MCP-02 (P1):** Read-only by default; tools that write files or start captures need explicit opt-in and per-call confirmation. Results default to field trees and summaries rather than raw payloads, with size limits.

**Privacy and safety controls**

- **AIP-01 (P1):** Local-only mode: a per-profile policy that blocks every non-loopback provider, enforced in code and not only in the UI.
- **AIP-02 (P1):** Data minimization: by default only field trees, statistics, and short payload excerpts are sent, never whole capture files. A preview shows the exact request before the first send and whenever the scope grows.
- **AIP-03 (P1):** Redaction before any cloud call: consistent per-session pseudonyms for IPs, MACs, and hostnames; removal of credentials, cookies, tokens, and authorization headers; user-defined regex rules. The reverse mapping stays on the machine so answers can be de-anonymized locally.
- **AIP-04 (P1):** Prompt-injection defense: packet content is untrusted data, delimited and labeled in prompts; model output is never executed; anything beyond display needs user confirmation.
- **AIP-05 (P1):** Local audit log of every request (provider, model, size, redaction summary, time), exportable; message content is stored only if the user turns that on.
- **AIP-06 (P1):** Evaluation harness with versioned prompts and golden sets (filter-generation accuracy, summary faithfulness) that runs against each supported provider on demand and in release CI.

**Provider interface (sketch)**

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    async fn chat(&self, req: ChatRequest) -> Result<ChatResponse, LlmError>;
    fn chat_stream(&self, req: ChatRequest) -> BoxStream<'static, Result<Delta, LlmError>>;
    async fn list_models(&self) -> Result<Vec<ModelInfo>, LlmError>;
}

pub struct ChatRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,                 // empty if unsupported
    pub response_schema: Option<JsonSchema>,  // structured output
    pub max_tokens: u32,
    pub temperature: f32,
}
```

## 7. Non-Functional Requirements

**Performance** (reference hardware: 8-core x86-64, 16 GB RAM, NVMe). These are targets to validate with early benchmarks, not guarantees.

- **PERF-01:** Capture to disk with zero kernel drops at 1 Gbit/s (small-packet mix); 10 Gbit/s on Linux with the AF\_PACKET backend (P2).
- **PERF-02:** Open a 1 GB pcap and show the first screen in under 2 s; index 10 million packets in under 30 s.
- **PERF-03:** Tier-1 dissection of at least 1 million packets/s across all cores in CLI mode (stretch: 2x TShark single-thread speed on the same corpus).
- **PERF-04:** Apply a filter over 10 million packets in under 5 s for indexed fields.
- **PERF-05:** GUI input latency under 50 ms; 60 fps scrolling.
- **PERF-06:** Index overhead of 150 bytes per packet or less; bounded resident memory for files larger than RAM.

**Reliability and safety**

- **REL-01:** `unsafe` is confined to designated crates (capture FFI, memory mapping, SIMD); every block is documented and reviewed, and CI tracks the count.
- **REL-02:** Zero panics on fuzzed input; panics are caught at the dissector boundary and reported as malformed-packet errors.
- **REL-03:** Hard limits on packet size, recursion depth, reassembly buffers, and decompression ratio (decompression-bomb protection).

**Portability**

- **PLT-01:** Windows 10+, macOS 12+, Linux (glibc and musl); x86-64 and ARM64; static CLI builds; GUI installers (MSI, DMG, AppImage/Flatpak, deb/rpm).
- **PLT-02:** Core library compiles to WebAssembly for in-browser PCAP viewing (P2).

**Security, privacy, usability**

- **SEC-01:** The capture helper holds the minimum privileges; the GUI never runs as root or Administrator.
- **SEC-02:** No telemetry by default; update checks are opt-in.
- **SEC-03:** Signed, reproducible releases with an SBOM; dependencies checked with cargo-audit and cargo-deny.
- **UX-01:** Externalized UI strings, RTL and CJK text support, documented shortcuts, and WCAG 2.1 AA conformance for GUI chrome.

## 8. System Architecture

**Workspace crates**

```
mung-ash/
├── mash-core        Packet, Timestamp, Interface, errors, field tree types
├── mash-capture     libpcap/Npcap/AF_PACKET backends, mash-cap helper protocol
├── mash-pcapfile    pcap, pcapng, third-party readers/writers, compression
├── mash-dissect     Dissector trait, tables, conversations, registry
├── mash-protocols   Dissectors grouped by feature flags per tier
├── mash-filter      Lexer, parser, type checker, compiler, evaluator
├── mash-reassembly  IP fragments, TCP streams, application buffers
├── mash-crypto      TLS/WPA/IPsec key schedules and decryption
├── mash-stats       Taps, conversations, I/O, TCP analysis, VoIP, expert info
├── mash-ai          LlmProvider trait, adapters (local, Google, Anthropic), redaction, prompts
├── mash-mcp         MCP server exposing captures and analysis to AI clients
├── mash-plugin      WASM host (Lua shim later)
├── mash-cli         mash, mash-edit, mash-merge, mash-info, mash-text2pcap
├── mash-gui         Desktop application
└── mash-cap         Privileged capture helper binary
```

**Data flow**

```
Interface/File → reader → bounded frame queue → index pass (offset, length, timestamp)
  → dissection worker pool (field trees, conversation lookup)
  → stateful second pass (TCP analysis, request/response) → taps/stats → GUI or CLI sink
                                                          ↘ mash-ai and mash-mcp (read-only consumers)
```

**Key design decisions**

- **Index first, dissect lazily.** Opening a file builds a compact frame index. Dissection runs in the background for filters and statistics, and on demand for the selected packet.
- **Parallel across flows, ordered within a flow.** Packets are sharded by flow hash so stateful analysis stays deterministic while using all cores. Results are cached in a columnar store keyed by frame number.
- **Compact arena-allocated field tree.** Nodes hold field ID, byte range, and value reference; display text is rendered lazily. This keeps memory low and filter evaluation allocation-free.
- **Registry as data.** Protocols and fields are registered at startup (ID, abbreviation, type, format, value strings). The registry powers filters, columns, auto-complete, and generated documentation.
- **Process model.** `mash-cap` (privileged) streams framed pcapng over a local socket or named pipe to the unprivileged GUI or CLI; the same protocol serves remote capture.
- **AI layer outside the hot path.** `mash-ai` and `mash-mcp` read computed statistics and field trees through the public library API, run on separate async tasks, and sit behind the `ai` feature flag. One provider trait with adapters for local runtimes, Google Gemini, and Claude keeps all vendor-specific code in a single crate (see 6.13).
- **GUI toolkit.** Decided by a Phase 0 spike among egui, Slint, Iced, and Tauri with a web front end. Criteria: a virtualized 10M-row list, accessibility, complex-script text rendering, and package size. The core stays GUI-agnostic.

## 9. Dissector Framework

```rust
pub trait Dissector: Send + Sync {
    fn id(&self) -> ProtocolId;
    fn dissect<'a>(&self, ctx: &mut DissectCtx<'a>, data: &'a [u8]) -> DissectResult;
    fn heuristic(&self, _ctx: &DissectCtx<'_>, _data: &[u8]) -> Confidence {
        Confidence::No
    }
}

pub struct DissectResult {
    pub consumed: usize,
    pub next: Next, // None, Table(TableId, Key), Dissector(ProtocolId), NeedMore(n)
    pub errors: SmallVec<[Malformed; 1]>,
}
```

- Each dissector declares its fields, tables, and preferences at registration; the registry rejects duplicate abbreviations.
- Dissectors write through typed builders (for example `ctx.add_u16(FIELD, range, value)`) that handle endianness, bit masks, and bounds centrally, so individual protocols cannot read out of range.
- A bounds-checked cursor converts truncation into a ‘truncated’ expert item instead of ad hoc error paths.
- Hand-written, DSL-generated, and WASM dissectors share one registry and tree format.
- Every dissector ships with a fixture capture, a golden-output test, and a fuzz target.

## 10. Display Filter Language

```
expr       := or_expr
or_expr    := and_expr ( ('||' | 'or') and_expr )*
and_expr   := not_expr ( ('&&' | 'and') not_expr )*
not_expr   := ('!' | 'not') not_expr | primary
primary    := '(' expr ')' | comparison | field        // bare field = presence test
comparison := operand op operand
op         := '==' | '!=' | '>' | '<' | '>=' | '<=' | 'contains' | 'matches' | 'in'
operand    := field ['[' slice ']'] | literal | set | function '(' args ')'
```

Examples:

- `ip.addr == 10.0.0.0/8 && tcp.port in {80 443 8080}`
- `tcp.analysis.retransmission || tcp.analysis.zero_window`
- `http.request.method == "POST" && frame.len > 1000`
- `dns.qry.name matches "^api"`

Semantics follow Wireshark: a field may occur several times per packet and `==` matches if any occurrence matches (all/any prefixes are an optional extension). Type errors are caught at compile time, and unknown fields produce an error with a did-you-mean suggestion.

## 11. Core Data Model

- **Frame:** number, timestamp (ns), captured and original length, link type, interface ID, comments, flags (marked, ignored, time reference).
- **Field node:** field ID, byte range (in the frame or a derived buffer), value, parent, expert severity.
- **Conversation:** key (protocol and endpoints), direction, counters, per-protocol state slots.
- **Data sources:** the original frame plus derived buffers (reassembled, decrypted, decompressed), each addressable in the bytes pane.

## 12. Security Considerations

- Treat every capture as hostile: files can be crafted to exhaust CPU, memory, or disk.
- Continuous fuzzing (cargo-fuzz, AFL++) of every dissector and file reader in CI, seeded from public captures, with OSS-Fuzz integration.
- Plugins run in a WASM sandbox with explicit capabilities; no filesystem or network access by default.
- Extracted objects: sanitize filenames, never execute content, warn before exporting decrypted data.
- Decryption secrets are zeroized and never logged.
- LLM features treat packet content as untrusted input (prompt injection): content is delimited in prompts, model output is never executed, and any action that changes state needs explicit confirmation.
- Cloud LLM calls are opt-in per profile, pass through the redaction pipeline (AIP-03), and can be blocked entirely with local-only mode; API keys stay in the OS keychain.

## 13. Testing and Quality

- **Differential testing against TShark** on a corpus of at least 5,000 traces (public sample captures and protocol conformance suites), comparing field abbreviations and values. A parity dashboard tracks agreement per protocol and gates releases.
- Unit, golden-file, and property tests (proptest) for dissectors and the filter language.
- Fuzzing, mutation of valid captures, and Miri and sanitizers on crates containing `unsafe`.
- Criterion benchmarks in CI with regression thresholds.
- GUI screenshot regression, accessibility audits, and scripted scenarios on all three operating systems.
- A 72-hour soak test at 500 Mbit/s with no memory growth.
- **AI layer:** record-and-replay contract tests for each LLM adapter (local, Gemini, Claude) and the evaluation harness (AIP-06) for filter-generation accuracy and summary faithfulness.

## 14. Licensing and Legal (decision required in Phase 0)

- Wireshark is licensed under GPL-2.0-or-later. Porting its dissectors would make MUNG-ASH a derivative work bound by that license. Choose between (a) a GPL-compatible project that may consult or port Wireshark code, or (b) a clean-room implementation from public RFCs and specifications under a permissive license (MIT or Apache-2.0). Obtain legal review before choosing.
- Do not use the Wireshark name, icon, or branding.
- Review licenses for bundled databases (OUI, services) and for Npcap redistribution; GeoIP data is user-supplied.
- Enforce dependency licenses with cargo-deny.

## 15. Roadmap

- **Phase 0, Foundations (4–6 weeks):** licensing decision, GUI spike, workspace skeleton, pcap/pcapng I/O, field registry, filter grammar, CI with fuzzing and the differential-test harness, and a design spike for the `LlmProvider` trait with one local-model adapter.
- **Phase 1, MVP (about 4–5 months):** CLI capture and read, Tier-1 dissectors, IP and TCP reassembly, display filters, three-pane GUI, basic statistics.
- **Phase 2, Analysis (about 4 months):** TCP analysis, Follow Stream, I/O graph, Expert Info, TLS key-log decryption, coloring rules, profiles, remaining CLI tools, and the AI assistant (AI-01 to AI-12) with local, Google Gemini, and Claude adapters plus the redaction pipeline.
- **Phase 3, v1.0 (about 4 months):** Tier-2 protocols, VoIP, export objects, WASM plugins, installers, documentation, external security audit, the MCP server (MCP-01, MCP-02), and the AI evaluation harness.
- **Phase 4, v1.x–2.0:** Tier-3 protocols, 802.11 and WPA decryption, Lua shim, Python bindings, web viewer, kernel-bypass capture, investigation chat, report drafting, dissector scaffolding, and in-process local inference.

Staffing assumption: 6–8 engineers (two on dissectors, one on capture and OS integration, one on filters, statistics, and the AI layer, two on GUI, one on QA, fuzzing, and infrastructure), one product manager, and a part-time designer. Protocol coverage is the long pole; timelines scale with team size.

## 16. Success Metrics

- **Parity:** at least 95% of Tier-1 and 90% of Tier-2 packets in the reference corpus produce field trees matching TShark.
- **Security:** no memory-safety CVEs; a documented fuzzing budget per release with no open crashers.
- **Performance:** PERF-01 to PERF-06 met on reference hardware.
- **AI (targets, to be validated):** at least 90% of natural-language filter requests in the evaluation set yield a valid filter on the reference hosted models and 75% on the reference local model; zero cloud requests in local-only mode.
- **Quality:** crash-free session rate of at least 99.5% (opt-in reporting only).
- **Adoption:** 10,000 monthly active users within 12 months of v1.0 and CLI use in public CI pipelines.

## 17. Risks and Mitigations

- **Protocol coverage is enormous.** Tiered scope, declarative DSL, WASM plugins, contributor guide, prioritization by corpus frequency.
- **Rust GUI maturity** (virtualized tables, complex text, accessibility). Early spike, GUI-agnostic core, budget for custom widgets.
- **Windows capture dependencies.** Verify Npcap licensing and redistribution terms; document the install flow.
- **Behavior mismatches with Wireshark.** Differential testing and a published list of intentional deviations.
- **Unproven performance targets.** Benchmark in Phase 1 and revise targets with data.
- **Licensing ambiguity.** Resolve in Phase 0 with legal review.
- **Scope creep toward IDS or analytics.** Enforce non-goals in roadmap reviews.
- **LLM variability and vendor API drift.** One provider trait, capability records, contract tests per adapter, versioned prompts, and fallback between providers.
- **Sensitive traffic leaving the machine.** Off by default, local-only mode, redaction, request preview, and an audit log.
- **Hallucinated or unfaithful AI output.** Ground answers in computed field trees and statistics, cite packet numbers, validate generated filters with the compiler, and label AI output as such.

## 18. Open Questions

1. Open source (which license) or commercial?
2. Final GUI toolkit?
3. Is the primary audience professional analysts (needing full parity) or educational and embedded users (needing a small footprint)?
4. Must display filters be exactly Wireshark-compatible, or is a cleaned-up superset acceptable?
5. Is Lua compatibility required to reuse existing community dissectors?
6. Which platforms block the launch?
7. Which AI features are must-have for v1.0, and which provider is the default for a new profile?
8. Should an offline build bundle a small local model, or require the user to run their own runtime such as Ollama?

## Appendix: Candidate Rust Crates

- **Capture:** pcap, nix/libc (AF\_PACKET), socket2.
- **File formats:** pcap-file, pcap-parser, flate2, zstd, lz4\_flex, memmap2.
- **Parsing:** nom, winnow, etherparse, byteorder, bitvec.
- **Filters:** logos, chumsky or pest, regex, ipnet.
- **Concurrency:** rayon, crossbeam, tokio (remote capture, async name resolution), dashmap.
- **Crypto:** RustCrypto (aes-gcm, chacha20poly1305, hmac, hkdf, sha2, rsa), ring, zeroize.
- **Storage:** arrow, rkyv, smallvec, bumpalo.
- **Plugins and bindings:** wasmtime, mlua, pyo3.
- **GUI:** egui, slint, iced, tauri; plotters for charts.
- **Testing:** proptest, cargo-fuzz, criterion, insta.
- **AI and MCP:** reqwest, serde, async-trait, futures, eventsource-stream (streaming), keyring (OS keychain), rmcp (Rust MCP SDK), llama-cpp-2 or candle (in-process inference); evaluate multi-provider crates such as genai or rig before writing custom adapters.
