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

//! Command-line / config-file options and the config-file parser.
//!
//! Ported from `CheckOpt` and `ReadConfig` in `cping.c`.

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

use anyhow::{bail, Result};

use crate::app::Target;
use crate::icmp::{ICMP_HDR_LEN, TS_LEN};
use crate::ping::{Ping, Stat, MAXSZ};

/// Options that can be set from the config file or the command line.
#[derive(Clone, Debug)]
pub struct Options {
    /// `-b` clears this: light-on-dark instead of dark-on-light.
    pub white: bool,
    /// `-n` clears this: show the hop-count column.
    pub hop: bool,
    /// `-r` clears this: scroll pings right-to-left.
    pub r2l: bool,
    /// `-a` sets this: show the address column.
    pub showip: bool,
    /// `-t` sets this: show the min/avg/max/lost columns.
    pub stat: bool,
    /// `-S` sets this: start silent.
    pub silent: bool,
    /// `-x` sets this to 3: numeric ping display. Also cycled by the `c` key.
    pub ich: i32,
    /// `-c` sets this: fixed ping glyph.
    pub pch: Option<char>,
    /// `-m`: minimum ICMP packet size.
    pub minsz: usize,
    /// `-s`: seconds between ping groups (1..=5).
    pub sbp: i64,
    /// `-p`: microseconds between individual pings.
    pub pus: u64,
    /// `-N`: stop after this many ping groups.
    pub num: i64,
    /// `-o`: log file path.
    pub out_path: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            white: true,
            hop: true,
            r2l: true,
            showip: false,
            stat: false,
            silent: false,
            ich: 0,
            pch: None,
            minsz: 0,
            sbp: 1,
            pus: 1000,
            num: 0,
            out_path: None,
        }
    }
}

/// C-style `atoi`: leading optional sign, then digits, stop at the first
/// non-digit, 0 if there are none.
fn atoi(s: &str) -> i64 {
    let s = s.trim_start();
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        i += 1;
    }
    let start_digits = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start_digits {
        return 0;
    }
    s[..i].parse().unwrap_or(0)
}

impl Options {
    /// Apply one option. Returns `Ok(true)` if `ch` is a known option,
    /// `Ok(false)` if not, `Err` for a bad value (`CheckOpt`).
    pub fn check_opt(&mut self, ch: char, arg: &str) -> Result<bool> {
        match ch {
            'b' => self.white = false,
            'n' => self.hop = false,
            'm' => {
                let m = atoi(arg);
                if m == 0 {
                    bail!("Invalid -m {arg}");
                }
                let m = m as usize;
                if m < ICMP_HDR_LEN + TS_LEN {
                    bail!("-m too small {arg}");
                }
                if m > MAXSZ {
                    bail!("-m too large {arg}");
                }
                self.minsz = m;
            }
            'r' => self.r2l = false,
            'p' => {
                let p = atoi(arg);
                if p < 1 {
                    bail!("Invalid -p {arg}");
                }
                self.pus = p as u64;
            }
            'a' => self.showip = true,
            'x' => self.ich = 3,
            't' => self.stat = true,
            's' => {
                let s = atoi(arg);
                if !(1..=5).contains(&s) {
                    bail!("Invalid -s {arg}");
                }
                self.sbp = s;
            }
            'c' => self.pch = arg.chars().next(),
            'o' => self.out_path = Some(arg.to_string()),
            'N' => {
                let n = atoi(arg);
                if n < 1 {
                    bail!("Invalid -N {n}");
                }
                self.num = n;
            }
            'S' => self.silent = true,
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// Result of parsing the config file.
pub struct Config {
    pub targets: Vec<Target>,
    pub nhdr: usize,
    pub nwid: usize,
    pub awid: usize,
}

/// Resolve a hostname / dotted quad to its first IPv4 address, like
/// `gethostbyname` taking `h_addr_list[0]`.
fn resolve(host: &str) -> Option<Ipv4Addr> {
    (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|s| match s {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
}

/// Read the first readable file from `files`, honouring embedded option lines
/// (`ReadConfig`).
pub fn read_config(files: &[String], opts: &mut Options) -> Result<Config> {
    let mut bytes = None;
    let mut opened = String::new();
    for f in files {
        if let Ok(b) = std::fs::read(f) {
            bytes = Some(b);
            opened = f.clone();
            break;
        }
    }
    let bytes = match bytes {
        Some(b) => b,
        None => {
            let mut msg = format!("Cannot open file {}", files[0]);
            for f in &files[1..] {
                msg.push_str(&format!(" or {f}"));
            }
            bail!(msg);
        }
    };

    // UTF-8 BOM check, mirroring the `magic` handling in `ReadConfig`.
    let start = if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        eprintln!("WARNING: UTF-8 file treated as ASCII");
        3
    } else {
        0
    };
    let text = String::from_utf8_lossy(&bytes[start..]).into_owned();

    let mut targets: Vec<Target> = Vec::new();
    let mut nhdr = 0usize;
    let mut nwid = 6usize;
    let mut awid = 6usize;
    let mut indent = 0usize;
    let mut hdr: Option<String> = None;

    for raw in text.lines() {
        // `#` in column 1 is a comment (checked before trimming, as in C).
        if raw.starts_with('#') {
            continue;
        }
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        let b0 = line.as_bytes()[0];

        // Header line.
        if b0 == b'>' {
            let text = &line[1..];
            if line.len() == 1 && indent > 0 {
                hdr = None;
            } else {
                nhdr += 1;
                hdr = Some(text.to_string());
            }
            indent = if line.len() > 1 { 3 } else { 0 };
            continue;
        }

        // Option line.
        if b0 == b'-' {
            let ch = line[1..].chars().next().unwrap_or('\0');
            let arg = line
                .get(2..)
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            match opts.check_opt(ch, arg) {
                Ok(true) => {}
                Ok(false) => bail!("Invalid option in config file\n{line}"),
                Err(e) => return Err(e),
            }
            continue;
        }

        // Target line: first whitespace-delimited token is the host, the rest
        // (from the first non-space after it) is the optional display name.
        let after_lead = line.trim_start();
        let lead = line.len() - after_lead.len();
        let host_end = after_lead
            .find(char::is_whitespace)
            .unwrap_or(after_lead.len());
        let host = &after_lead[..host_end];
        if host.is_empty() {
            bail!("Error reading address: {line}");
        }
        let rest = &after_lead[host_end..];
        let ws = rest.len() - rest.trim_start().len();
        let i = lead + host_end + ws;
        let display = line.get(i..).unwrap_or("");

        let (name, host_field) = if !display.is_empty() {
            let l = display.len() + indent;
            if l > nwid {
                nwid = l;
            }
            if host.len() > awid {
                awid = host.len();
            }
            (format!("{}{}", " ".repeat(indent), display), host.to_string())
        } else {
            let l = host.len() + indent;
            if l > nwid {
                nwid = l;
            }
            (format!("{}{}", " ".repeat(indent), host), String::new())
        };

        let ip = resolve(host)
            .ok_or_else(|| anyhow::anyhow!("Cannot resolve host name {host}"))?;

        if targets.iter().any(|t| t.ip == ip) {
            bail!("{name} has a duplicate IP");
        }

        targets.push(Target {
            hdr: hdr.take(),
            name,
            host: host_field,
            silent: false,
            dt: -1.0,
            ping: Ping::new(),
            stat: Stat::new(),
            ttl: 0,
            ip,
        });
    }

    if targets.is_empty() {
        bail!("No targets in {opened}");
    }

    Ok(Config {
        targets,
        nhdr,
        nwid,
        awid,
    })
}
