use flate2::read::{GzDecoder, ZlibDecoder};
use mash_core::{MashError, Result, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;

/// Maximum reassembled TCP stream buffer per direction (16 MiB default, REA-05).
pub const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;
/// Maximum decompressed HTTP body size (16 MiB default, REL-03).
pub const MAX_HTTP_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// Policy for resolving overlapping IP fragments or TCP segments (`REA-01`, `REA-02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OverlapPolicy {
    /// Keep original bytes when a later fragment/segment overlaps.
    #[default]
    FirstWins,
    /// Overwrite with the newly arrived bytes.
    LastWins,
}

/// Key identifying an IPv4 fragmented datagram (`REA-01`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4FragKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    pub ident: u16,
}

#[derive(Debug, Clone, Default)]
struct FragBuffer {
    fragments: BTreeMap<usize, Vec<u8>>,
    total_len: Option<usize>,
    had_overlap: bool,
    frame_numbers: Vec<u64>,
}

/// Result of feeding an IPv4 fragment into `IpDefragmenter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledDatagram {
    pub payload: Vec<u8>,
    pub fragment_frames: Vec<u64>,
    pub had_overlap: bool,
}

/// Stateful IPv4 fragment reassembler (`REA-01`).
#[derive(Debug, Clone, Default)]
pub struct IpDefragmenter {
    pub policy: OverlapPolicy,
    active: HashMap<Ipv4FragKey, FragBuffer>,
}

impl IpDefragmenter {
    pub fn new(policy: OverlapPolicy) -> Self {
        Self {
            policy,
            active: HashMap::new(),
        }
    }

    /// Feed an IPv4 fragment (`frag_offset_bytes`, `more_fragments`, `payload`).
    /// Returns `Some(ReassembledDatagram)` when all bytes `0..total_len` have arrived.
    pub fn push_ipv4_fragment(
        &mut self,
        key: Ipv4FragKey,
        frame_number: u64,
        frag_offset_bytes: usize,
        more_fragments: bool,
        payload: &[u8],
    ) -> Option<ReassembledDatagram> {
        if !more_fragments && frag_offset_bytes == 0 {
            return None; // Unfragmented packet
        }
        if frag_offset_bytes.saturating_add(payload.len()) > 65_535 {
            return None;
        }

        let entry = self.active.entry(key.clone()).or_default();
        if !entry.frame_numbers.contains(&frame_number) {
            entry.frame_numbers.push(frame_number);
        }
        if !more_fragments {
            entry.total_len = Some(frag_offset_bytes + payload.len());
        }

        // Check for overlap with existing fragments
        let new_start = frag_offset_bytes;
        let new_end = frag_offset_bytes + payload.len();
        for (&off, existing) in &entry.fragments {
            let ex_end = off + existing.len();
            if new_start < ex_end && off < new_end {
                entry.had_overlap = true;
            }
        }
        entry.fragments.insert(frag_offset_bytes, payload.to_vec());

        let total = entry.total_len?;
        // Verify contiguous coverage from 0..total
        let mut covered = 0usize;
        for (&off, data) in &entry.fragments {
            if off > covered {
                return None; // Hole still present
            }
            covered = covered.max(off + data.len());
        }
        if covered < total {
            return None;
        }

        // Reconstruct final buffer according to overlap policy
        let finished = self.active.remove(&key)?;
        let mut out = vec![0u8; total];
        let mut written = vec![false; total];
        for (off, data) in finished.fragments {
            for (i, &b) in data.iter().enumerate() {
                let pos = off + i;
                if pos < total && (!written[pos] || self.policy == OverlapPolicy::LastWins) {
                    out[pos] = b;
                    written[pos] = true;
                }
            }
        }

        Some(ReassembledDatagram {
            payload: out,
            fragment_frames: finished.frame_numbers,
            had_overlap: finished.had_overlap,
        })
    }
}

/// A single directional payload chunk in a reassembled stream (`STA-01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamChunk {
    pub frame_number: u64,
    pub timestamp: Timestamp,
    pub from_client: bool,
    pub data: Vec<u8>,
}

/// Output display format for "Follow Stream" (`STA-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamDisplayFormat {
    Ascii,
    Utf8,
    HexDump,
    RawHex,
}

#[derive(Debug, Clone, Default)]
struct HalfStream {
    isn: Option<u32>,
    next_seq: u32,
    contiguous: Vec<u8>,
    out_of_order: BTreeMap<u32, (u64, Timestamp, Vec<u8>)>,
    retransmissions: u64,
}

/// Reassembled bidirectional TCP or UDP conversation stream (`REA-02`, `STA-01`).
#[derive(Debug, Clone, Default)]
pub struct ReassembledStream {
    pub stream_id: u32,
    pub client_endpoint: Option<(String, u16)>,
    pub server_endpoint: Option<(String, u16)>,
    pub chunks: Vec<StreamChunk>,
    client_half: HalfStream,
    server_half: HalfStream,
}

impl ReassembledStream {
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            ..Self::default()
        }
    }

    /// Push a TCP segment into the stream reassembler, handling SYN sequence numbers, out-of-order segments, and retransmissions.
    #[allow(clippy::too_many_arguments)]
    pub fn push_tcp_segment(
        &mut self,
        frame_number: u64,
        timestamp: Timestamp,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        seq: u32,
        is_syn: bool,
        payload: &[u8],
    ) {
        let ep_src = (src_ip.to_string(), src_port);
        let ep_dst = (dst_ip.to_string(), dst_port);
        if self.client_endpoint.is_none() {
            self.client_endpoint = Some(ep_src.clone());
            self.server_endpoint = Some(ep_dst);
        }
        let from_client = self.client_endpoint.as_ref() == Some(&ep_src);
        let half = if from_client {
            &mut self.client_half
        } else {
            &mut self.server_half
        };

        if half.isn.is_none() {
            let initial = if is_syn { seq.wrapping_add(1) } else { seq };
            half.isn = Some(initial);
            half.next_seq = initial;
        }

        if payload.is_empty() {
            return;
        }
        if half.contiguous.len() + payload.len() > MAX_STREAM_BYTES {
            return;
        }

        let data_seq = if is_syn { seq.wrapping_add(1) } else { seq };
        if data_seq == half.next_seq {
            half.contiguous.extend_from_slice(payload);
            half.next_seq = half.next_seq.wrapping_add(payload.len() as u32);
            self.chunks.push(StreamChunk {
                frame_number,
                timestamp,
                from_client,
                data: payload.to_vec(),
            });

            // Drain any newly contiguous out-of-order segments
            while let Some((ooo_frame, ooo_ts, ooo_data)) = half.out_of_order.remove(&half.next_seq)
            {
                half.contiguous.extend_from_slice(&ooo_data);
                half.next_seq = half.next_seq.wrapping_add(ooo_data.len() as u32);
                self.chunks.push(StreamChunk {
                    frame_number: ooo_frame,
                    timestamp: ooo_ts,
                    from_client,
                    data: ooo_data,
                });
            }
        } else if seq_before(data_seq, half.next_seq) {
            // Retransmission or partial overlap
            half.retransmissions += 1;
            let end_seq = data_seq.wrapping_add(payload.len() as u32);
            if seq_before(half.next_seq, end_seq) {
                let new_bytes_len = end_seq.wrapping_sub(half.next_seq) as usize;
                if new_bytes_len <= payload.len() {
                    let tail = &payload[payload.len() - new_bytes_len..];
                    half.contiguous.extend_from_slice(tail);
                    half.next_seq = end_seq;
                    self.chunks.push(StreamChunk {
                        frame_number,
                        timestamp,
                        from_client,
                        data: tail.to_vec(),
                    });
                }
            }
        } else if half.out_of_order.len() < 1024 {
            half.out_of_order
                .insert(data_seq, (frame_number, timestamp, payload.to_vec()));
        }
    }

    /// Push a UDP datagram payload into the conversation stream (`STA-01`).
    #[allow(clippy::too_many_arguments)]
    pub fn push_udp_datagram(
        &mut self,
        frame_number: u64,
        timestamp: Timestamp,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        payload: &[u8],
    ) {
        if payload.is_empty() {
            return;
        }
        let ep_src = (src_ip.to_string(), src_port);
        let ep_dst = (dst_ip.to_string(), dst_port);
        if self.client_endpoint.is_none() {
            self.client_endpoint = Some(ep_src.clone());
            self.server_endpoint = Some(ep_dst);
        }
        let from_client = self.client_endpoint.as_ref() == Some(&ep_src);
        self.chunks.push(StreamChunk {
            frame_number,
            timestamp,
            from_client,
            data: payload.to_vec(),
        });
    }

    pub fn client_bytes(&self) -> &[u8] {
        &self.client_half.contiguous
    }

    pub fn server_bytes(&self) -> &[u8] {
        &self.server_half.contiguous
    }

    /// Format the conversation stream for "Follow Stream" display (`STA-01`).
    pub fn format_stream(&self, fmt: StreamDisplayFormat) -> String {
        let mut out = String::new();
        for chunk in &self.chunks {
            let dir_tag = if chunk.from_client { "C->S" } else { "S->C" };
            match fmt {
                StreamDisplayFormat::Ascii => {
                    let text: String = chunk
                        .data
                        .iter()
                        .map(|&b| {
                            if b == b'\r' || b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b)
                            {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    out.push_str(&text);
                }
                StreamDisplayFormat::Utf8 => {
                    out.push_str(&String::from_utf8_lossy(&chunk.data));
                }
                StreamDisplayFormat::RawHex => {
                    for &b in &chunk.data {
                        out.push_str(&format!("{b:02x}"));
                    }
                    out.push('\n');
                }
                StreamDisplayFormat::HexDump => {
                    out.push_str(&format!(
                        "--- Frame {} ({dir_tag}, {} bytes) ---\n",
                        chunk.frame_number,
                        chunk.data.len()
                    ));
                    for (idx, line) in chunk.data.chunks(16).enumerate() {
                        let off = idx * 16;
                        let hex: Vec<String> = line.iter().map(|b| format!("{b:02x}")).collect();
                        let ascii: String = line
                            .iter()
                            .map(|&b| {
                                if (0x20..=0x7e).contains(&b) {
                                    b as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        out.push_str(&format!("{off:04x}  {:<47}  {ascii}\n", hex.join(" ")));
                    }
                }
            }
        }
        out
    }
}

fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Decompress an HTTP body compressed with `gzip` or `deflate`, enforcing `MAX_HTTP_DECOMPRESSED_BYTES` (`REA-04`, `REL-03`).
pub fn decompress_http_body(content_encoding: &str, compressed: &[u8]) -> Result<Vec<u8>> {
    let enc = content_encoding.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    if enc.contains("gzip") || enc.contains("x-gzip") {
        let decoder = GzDecoder::new(compressed);
        let mut limited = decoder.take((MAX_HTTP_DECOMPRESSED_BYTES as u64) + 1);
        limited.read_to_end(&mut out)?;
    } else if enc.contains("deflate") {
        let decoder = ZlibDecoder::new(compressed);
        let mut limited = decoder.take((MAX_HTTP_DECOMPRESSED_BYTES as u64) + 1);
        limited.read_to_end(&mut out)?;
    } else {
        return Ok(compressed.to_vec());
    }

    if out.len() > MAX_HTTP_DECOMPRESSED_BYTES {
        return Err(MashError::LimitExceeded(
            "HTTP compressed body exceeds 16 MiB decompression limit".to_string(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn ipv4_fragment_reassembly_handles_out_of_order_and_overlaps() {
        let mut defrag = IpDefragmenter::new(OverlapPolicy::FirstWins);
        let key = Ipv4FragKey {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            proto: 17,
            ident: 0x1234,
        };

        // Send second fragment first (offset 8, last fragment)
        assert!(defrag
            .push_ipv4_fragment(key.clone(), 1, 8, false, b"WORLD!")
            .is_none());
        // Send first fragment (offset 0, more_fragments = true)
        let res = defrag
            .push_ipv4_fragment(key, 2, 0, true, b"HELLO___")
            .unwrap();
        assert_eq!(res.payload, b"HELLO___WORLD!");
        assert_eq!(res.fragment_frames, vec![1, 2]);
        assert!(!res.had_overlap);
    }

    #[test]
    fn tcp_stream_reassembly_orders_segments_and_deduplicates_retransmissions() {
        let mut stream = ReassembledStream::new(0);
        let t = Timestamp::ZERO;
        // Out-of-order segment seq=105 ("WORLD") arrives before seq=100 ("HELLO")
        stream.push_tcp_segment(1, t, "10.0.0.1", 12345, "10.0.0.2", 80, 100, true, b"");
        stream.push_tcp_segment(2, t, "10.0.0.1", 12345, "10.0.0.2", 80, 106, false, b"WORLD");
        stream.push_tcp_segment(3, t, "10.0.0.1", 12345, "10.0.0.2", 80, 101, false, b"HELLO");
        // Retransmission of seq=101 ("HELLO")
        stream.push_tcp_segment(4, t, "10.0.0.1", 12345, "10.0.0.2", 80, 101, false, b"HELLO");

        assert_eq!(stream.client_bytes(), b"HELLOWORLD");
        assert_eq!(stream.format_stream(StreamDisplayFormat::Ascii), "HELLOWORLD");
    }

    #[test]
    fn http_gzip_decompression_roundtrip() {
        let body = b"{\"status\":\"ok\",\"items\":[1,2,3]}";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(body).unwrap();
        let compressed = enc.finish().unwrap();

        let decompressed = decompress_http_body("gzip", &compressed).unwrap();
        assert_eq!(decompressed, body);
    }
}
