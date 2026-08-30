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

//! Ping history ring buffer, per-target statistics and the log-scale byte
//! encoding used to store one sample per second.
//!
//! Ported from the `Ping`/`Stat` structs and the `InitPing`, `SetPing`,
//! `GetPing`, `PingShift`, `InitStat`, `Stats` and `ByteTime` functions in
//! `cping.c`.

/// Program version, mirrors `#define VER` in `cping.c`.
pub const VER: &str = "2.4.0";

/// Maximum length of the ping history, in seconds (`#define nsec`).
pub const NSEC: usize = 3600;

/// TTL used for target pings (`#define pTTL`).
pub const P_TTL: u32 = 64;
/// Maximum TTL / number of hops probed by the parallel traceroute
/// (`#define tTTL`).
pub const T_TTL: usize = 24;

/// Maximum ICMP packet size (`#define MAXSZ`).
pub const MAXSZ: usize = 1024;

// Special sample values (`enum {NoPing,LostPing,LatePing}`).
/// No ping has been recorded for this slot yet.
pub const NO_PING: u8 = 0xFF;
/// The reply was never received.
pub const LOST_PING: u8 = 0xFE;
/// The reply arrived, but more than one period late.
pub const LATE_PING: u8 = 0xFD;

/// Encode a round-trip time (milliseconds) into a single byte.
///
/// Upper nibble is the base-10 exponent (used to pick the display colour),
/// lower nibble is the mantissa digit 0-9. Example: `0x25` == 500 ms.
/// Values of 10000 ms or more are treated as lost. Mirrors `ByteTime`.
pub fn byte_time(dt: f64) -> u8 {
    let idt = (dt + 0.5) as i64; // truncates toward zero, like the C cast
    if idt < 10 {
        idt as u8
    } else if idt < 100 {
        (idt / 10) as u8 + 0x10
    } else if idt < 1000 {
        (idt / 100) as u8 + 0x20
    } else if idt < 10000 {
        (idt / 1000) as u8 + 0x30
    } else {
        LOST_PING
    }
}

/// Per-target / per-hop running statistics (`typedef struct { ... } Stat`).
#[derive(Clone, Debug)]
pub struct Stat {
    /// Number of replies counted.
    pub n: i64,
    /// Sum of round-trip times.
    pub s: f64,
    /// Sum of squares of round-trip times.
    pub s2: f64,
    /// Minimum round-trip time, or -1 when unset.
    pub min: f64,
    /// Maximum round-trip time, or -1 when unset.
    pub max: f64,
    /// Mean round-trip time, or -1 when unset.
    pub avg: f64,
    /// Sample standard deviation, or -1 when unset.
    pub std: f64,
    /// Lost packets, or -1 before the first shift.
    pub lost: i64,
    /// Late packets (reply arrived after its period).
    pub late: i64,
}

impl Default for Stat {
    fn default() -> Self {
        Self::new()
    }
}

impl Stat {
    /// Equivalent of `InitStat`.
    pub fn new() -> Self {
        Stat {
            n: 0,
            s: 0.0,
            s2: 0.0,
            min: -1.0,
            max: -1.0,
            avg: -1.0,
            std: -1.0,
            lost: -1,
            late: 0,
        }
    }

    /// Fold a new round-trip time into the statistics (`Stats`).
    pub fn update(&mut self, dt: f64) {
        self.n += 1;
        self.s += dt;
        self.s2 += dt * dt;
        if self.min < 0.0 || dt < self.min {
            self.min = dt;
        }
        if self.max < 0.0 || dt > self.max {
            self.max = dt;
        }
        let n = self.n as f64;
        self.avg = self.s / n;
        self.std = if self.n > 1 {
            ((self.s2 - self.s * self.s / n) / (n - 1.0)).sqrt()
        } else {
            0.0
        };
    }
}

/// Ring buffer of one-byte replies, one slot per second (`typedef struct Ping`).
#[derive(Clone)]
pub struct Ping {
    cur: usize,
    buf: Box<[u8; NSEC]>,
}

impl Default for Ping {
    fn default() -> Self {
        Self::new()
    }
}

impl Ping {
    /// Equivalent of `InitPing`.
    pub fn new() -> Self {
        Ping {
            cur: NSEC - 1,
            buf: Box::new([NO_PING; NSEC]),
        }
    }

    /// Store `val` at offset `off` from the current slot (`SetPing`).
    pub fn set(&mut self, off: usize, val: u8) {
        let k = (self.cur + off) % NSEC;
        self.buf[k] = val;
    }

    /// Read the slot at offset `off`, shifted back in time by `delt`
    /// seconds (`GetPing`; the C version folds in the global `delt`).
    pub fn get(&self, off: usize, delt: usize) -> u8 {
        let k = (self.cur + off + delt) % NSEC;
        self.buf[k]
    }

    /// Advance the buffer by one second, folding a lost count into `stat`
    /// and seeding the new slot as lost (`PingShift`).
    pub fn shift(&mut self, stat: &mut Stat) {
        if stat.lost < 0 {
            stat.lost = 0;
        } else if self.get(0, 0) == LOST_PING && stat.lost < 99999 {
            stat.lost += 1;
        }
        self.cur = if self.cur == 0 { NSEC - 1 } else { self.cur - 1 };
        self.set(0, LOST_PING);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_time_matches_reference() {
        assert_eq!(byte_time(0.0), 0x00);
        assert_eq!(byte_time(9.4), 0x09);
        assert_eq!(byte_time(9.6), 0x11); // rounds to 10 -> exp 1, mantissa 1
        assert_eq!(byte_time(42.0), 0x14);
        assert_eq!(byte_time(500.0), 0x25);
        assert_eq!(byte_time(1500.0), 0x31);
        assert_eq!(byte_time(20000.0), LOST_PING);
    }

    #[test]
    fn ping_shift_counts_losses() {
        let mut p = Ping::new();
        let mut s = Stat::new();
        p.shift(&mut s); // first shift only initialises lost to 0
        assert_eq!(s.lost, 0);
        p.shift(&mut s); // previous slot still Lost -> counted
        assert_eq!(s.lost, 1);
        p.set(0, byte_time(5.0)); // answer the current slot
        p.shift(&mut s);
        assert_eq!(s.lost, 1);
    }
}
