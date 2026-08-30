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

//! Reverse-DNS cache for traceroute hops.
//!
//! Ported from `InitDNS` / `nslookup` in `cping.c`. Only the main (render)
//! thread touches this, so no locking is required.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Cached `addr` (dotted quad) and `fqdn` (reverse name, or the dotted quad
/// again when the lookup fails) for each hop IP seen so far.
pub struct DnsCache {
    map: HashMap<Ipv4Addr, (String, String)>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        // dns[0] in the C code: the "no reply" placeholder.
        map.insert(Ipv4Addr::UNSPECIFIED, ("*".to_string(), "*".to_string()));
        DnsCache { map }
    }

    /// Look up `ip`, resolving and caching it on first sight. Returns
    /// `(addr_text, fqdn)`.
    pub fn lookup(&mut self, ip: Ipv4Addr) -> (&str, &str) {
        let entry = self.map.entry(ip).or_insert_with(|| {
            let addr = ip.to_string();
            let fqdn = dns_lookup::lookup_addr(&IpAddr::V4(ip)).unwrap_or_else(|_| addr.clone());
            (addr, fqdn)
        });
        (&entry.0, &entry.1)
    }
}
