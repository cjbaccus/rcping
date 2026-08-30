// rcping (cping-rs) - Concurrent Ping / Traceroute TUI
// Copyright (C) 2026 Carl Baccus
//
// This is a Rust port of cping by Willem A. Schreuder (AC0KQ)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

//! ICMP echo packet construction and IP/ICMP header parsing.
//!
//! Ported from `checksum`, `ICMP` and `UnpackHeader` in `cping.c`. As in the
//! original, multi-byte fields (id, sequence, the `f64` timestamp payload) are
//! written and read in the host's native byte order: both ends of the
//! conversation are the same machine, so the encoding only has to be
//! self-consistent.

use crate::ping::MAXSZ;

/// ICMP message types (values are the same on Linux and the BSDs).
pub const ICMP_ECHOREPLY: u8 = 0;
pub const ICMP_UNREACH: u8 = 3;
pub const ICMP_ECHO: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// Size of the ICMP header we emit (type, code, checksum, id, sequence).
pub const ICMP_HDR_LEN: usize = 8;
/// Minimum size of the IPv4 header.
pub const IP_HDR_MIN: usize = 20;
/// Size of the `f64` timestamp carried as the echo payload.
pub const TS_LEN: usize = 8;

/// Internet checksum over `data` (`checksum` in `cping.c`).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_ne_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        // C: `*(unsigned char*)(&csum) = *(unsigned char*)word;`
        sum += u16::from_ne_bytes([*b, 0]) as u32;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    !(sum as u16)
}

/// Build an ICMP echo request, padded with zero bytes to at least `minsz`
/// (`ICMP` in `cping.c`). `ts` is the payload timestamp in seconds.
pub fn build_echo(id: u16, seq: u16, minsz: usize, ts: f64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(minsz.clamp(ICMP_HDR_LEN + TS_LEN, MAXSZ));
    buf.push(ICMP_ECHO);
    buf.push(0); // code
    buf.extend_from_slice(&0u16.to_ne_bytes()); // checksum placeholder
    buf.extend_from_slice(&id.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&ts.to_ne_bytes());
    while buf.len() < minsz {
        buf.push(0);
    }
    let csum = checksum(&buf);
    buf[2..4].copy_from_slice(&csum.to_ne_bytes());
    buf
}

/// Parsed IP + ICMP header fields.
pub struct Header {
    /// Number of bytes consumed (IP header + ICMP header).
    pub len: usize,
    /// IP time-to-live of the received packet.
    pub ttl: u8,
    /// ICMP type.
    pub rtp: u8,
    /// ICMP code.
    #[allow(dead_code)]
    pub rcd: u8,
    /// Echo id.
    pub rid: u16,
    /// Echo sequence number.
    pub rsq: u16,
}

/// Parse the leading IPv4 + ICMP headers of `data` (`UnpackHeader`).
/// Returns `None` if the buffer is too short.
pub fn unpack_header(data: &[u8]) -> Option<Header> {
    if data.len() < IP_HDR_MIN {
        return None;
    }
    let ttl = data[8];
    let hlen = ((data[0] & 0x0f) as usize) << 2;
    let icp = data.get(hlen..hlen + ICMP_HDR_LEN)?;
    Some(Header {
        len: hlen + ICMP_HDR_LEN,
        ttl,
        rtp: icp[0],
        rcd: icp[1],
        rid: u16::from_ne_bytes([icp[4], icp[5]]),
        rsq: u16::from_ne_bytes([icp[6], icp[7]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_valid_packet_is_zero() {
        let pkt = build_echo(0x1234, 7, 0, 1234.5);
        // Re-summing a packet that already carries its checksum yields 0.
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn build_echo_pads_to_minsz() {
        let pkt = build_echo(1, 1, 64, 0.0);
        assert_eq!(pkt.len(), 64);
        assert_eq!(pkt[0], ICMP_ECHO);
    }

    #[test]
    fn roundtrip_header() {
        // Fake IPv4 header (ihl=5) followed by an ICMP echo reply.
        let mut buf = vec![0u8; IP_HDR_MIN];
        buf[0] = 0x45;
        buf[8] = 55; // ttl
        buf.extend_from_slice(&build_echo(0xABCD, 99, 0, 3.0));
        let h = unpack_header(&buf).unwrap();
        assert_eq!(h.ttl, 55);
        assert_eq!(h.rtp, ICMP_ECHO);
        assert_eq!(h.rid, 0xABCD);
        assert_eq!(h.rsq, 99);
        assert_eq!(h.len, IP_HDR_MIN + ICMP_HDR_LEN);
    }
}
