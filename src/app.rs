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

//! Shared application state and the geometry / scrolling logic.
//!
//! `App` is what the sender thread, the receiver thread and the render loop
//! all share behind a single `Mutex`. It corresponds to the pile of globals in
//! `cping.c` (`pt`, `tt`, `seq`, `mode`, `delt`, `sel`, `top`, the display
//! toggles, …). Values that never change after startup live in `Params`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use socket2::SockAddr;

use crate::ping::{Ping, Stat, NSEC, T_TTL};

/// Immutable run parameters (command line / config options that have no
/// runtime toggle).
#[derive(Clone, Copy)]
pub struct Params {
    /// Minimum ICMP packet size (`-m`), 0 for "no minimum".
    pub minsz: usize,
    /// Microseconds between successive pings (`-p`).
    pub pus: u64,
    /// Seconds between ping groups (`-s`).
    pub sbp: i64,
    /// Stop after this many ping groups (`-N`), 0 for "run forever".
    pub num: i64,
    /// Echo id identifying our target pings.
    pub pingid: u16,
    /// Echo id identifying our traceroute probes.
    pub traceid: u16,
}

/// A single ping target (`typedef struct { ... } Target`).
pub struct Target {
    /// Optional header printed above this row.
    pub hdr: Option<String>,
    /// Display name (already indented).
    pub name: String,
    /// Host text as written in the config file (empty when the display name
    /// was derived from it).
    pub host: String,
    /// Suppress the bell for this target.
    pub silent: bool,
    /// Last round-trip time in ms, or -1.
    pub dt: f64,
    /// Reply history.
    pub ping: Ping,
    /// Running statistics.
    pub stat: Stat,
    /// TTL of the last reply (used to estimate hop count).
    pub ttl: u8,
    /// Resolved IPv4 address.
    pub ip: Ipv4Addr,
}

impl Target {
    /// Destination socket address for `send_to`.
    pub fn sockaddr(&self) -> SockAddr {
        SockAddr::from(SocketAddr::V4(SocketAddrV4::new(self.ip, 0)))
    }
}

/// One traceroute hop (`typedef struct { ... } Trace`).
pub struct Trace {
    /// Responding IP, or `0.0.0.0` when no response yet.
    pub ip: Ipv4Addr,
    /// Last round-trip time in ms; 0 = pending, -1 = unreachable.
    pub dt: f64,
    /// Reply history.
    pub ping: Ping,
    /// Running statistics.
    pub stat: Stat,
}

impl Trace {
    pub fn new() -> Self {
        Trace {
            ip: Ipv4Addr::UNSPECIFIED,
            dt: 0.0,
            ping: Ping::new(),
            stat: Stat::new(),
        }
    }
}

impl Default for Trace {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything the threads share.
pub struct App {
    pub targets: Vec<Target>,
    pub traces: Vec<Trace>,
    /// Number of header lines (used for the "does it all fit" test).
    pub nhdr: usize,
    /// Display-name column width.
    pub nwid: usize,
    /// Address column width.
    pub awid: usize,

    /// Ping sequence number.
    pub seq: i32,
    /// Traceroute sequence number.
    pub tseq: i32,
    /// Current number of traceroute hops.
    pub nhop: usize,

    /// 0 = ping, 1 = traceroute, -1 = help.
    pub mode: i32,
    /// Time offset in seconds for history review.
    pub delt: i64,
    /// Selected target index.
    pub sel: usize,
    /// Index of the first visible row.
    pub top: usize,

    // Display toggles (seeded from `Options`).
    pub white: bool,
    pub r2l: bool,
    pub hop: bool,
    pub stat: bool,
    pub showip: bool,
    pub silent: bool,
    pub ich: i32,
    pub pch: Option<char>,

    // Terminal geometry.
    pub wid: u16,
    pub hgt: u16,
    /// Number of ping columns that fit (may be computed negative → treat as 0).
    pub nping: i64,

    /// Total ping groups sent (for the log footer).
    pub total: i64,
    /// Optional log file.
    pub out: Option<std::fs::File>,
}

impl App {
    /// Bottom-most fully visible row given a `top` (`Bottom` in `cping.c`).
    pub fn bottom(&self, top: usize) -> usize {
        let ntar = self.targets.len();
        let hgt = self.hgt as usize;
        let mut i = if ntar + self.nhdr + 1 < hgt || hgt > 20 {
            2
        } else {
            1
        };
        for k in top..ntar {
            i += if self.targets[k].hdr.is_some() { 2 } else { 1 };
            if i == hgt {
                return k;
            }
            if i > hgt {
                return k.saturating_sub(1);
            }
        }
        ntar.saturating_sub(1)
    }

    /// Keep `top` and `sel` consistent after a scroll or resize (`Scroll`).
    /// `dir` > 0 scrolls down, < 0 up, 0 is a resize.
    pub fn scroll(&mut self, dir: i32) {
        let ntar = self.targets.len();
        let hgt = self.hgt as usize;

        if ntar + self.nhdr + 1 < hgt {
            self.top = 0;
        } else if self.mode == 0 {
            let mut bot = self.bottom(self.top);
            if dir > 0 {
                let mut n = 0;
                while n < dir && self.bottom(self.top) < ntar - 1 {
                    self.top += 1;
                    bot = self.bottom(self.top);
                    n += 1;
                }
            } else if dir < 0 {
                self.top = (self.top as i32 + dir).max(0) as usize;
                bot = self.bottom(self.top);
            }
            if self.sel < self.top {
                self.sel = self.top;
            }
            if self.sel > bot {
                self.sel = bot;
            }
        } else if dir == 0 {
            let bot = self.bottom(self.top);
            if self.sel < self.top {
                self.top = self.sel;
            }
            if self.sel > bot {
                self.top = self.top.saturating_sub(self.sel - bot);
            }
        }
    }

    /// Recompute geometry-derived values (`Resize`).
    pub fn resize(&mut self, wid: u16, hgt: u16) {
        let nx = if self.hop {
            self.nwid + 9
        } else {
            self.nwid + 6
        } + if self.showip { self.awid + 1 } else { 0 };

        self.wid = wid;
        self.hgt = hgt;
        self.scroll(0);

        let mut nping = wid as i64 - nx as i64;
        if self.stat {
            nping -= 23;
        }
        if nping > NSEC as i64 {
            nping = NSEC as i64;
        }
        self.nping = nping;
    }

    /// Move the selection and scroll it into view (`newsel`).
    pub fn newsel(&mut self, dir: i32) {
        let ntar = self.targets.len() as i32;
        let new = (self.sel as i32 + dir).clamp(0, ntar - 1);
        if dir < 0 {
            while (new as usize) < self.top {
                self.scroll(-1);
            }
        } else {
            while new as usize > self.bottom(self.top) {
                self.scroll(1);
            }
        }
        self.sel = new as usize;
        self.nhop = 0;
        self.init_trace();
    }

    /// Reset the traceroute buffers (`InitTrace`).
    pub fn init_trace(&mut self) {
        self.tseq = 0;
        for tr in &mut self.traces {
            tr.stat = Stat::new();
            tr.ping = Ping::new();
        }
    }

    /// Clear all statistics (the `0` key).
    pub fn reset_stats(&mut self) {
        for tr in &mut self.traces {
            tr.stat = Stat::new();
        }
        for t in &mut self.targets {
            t.stat = Stat::new();
        }
    }
}

/// Build the initial traceroute vector.
pub fn new_traces() -> Vec<Trace> {
    (0..T_TTL).map(|_| Trace::new()).collect()
}
