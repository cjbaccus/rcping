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

//! Small helpers shared across modules.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time in seconds as an `f64` (`now()` in `cping.c`,
/// which used `gettimeofday`).
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Format a Unix timestamp as local time `YYYY-MM-DD<sep>HH:MM:SS`.
///
/// `sep` is a space for the on-screen clock and `-` for the log file, matching
/// the two `printf` formats in `cping.c`.
pub fn fmt_local(t: i64, sep: char) -> String {
    // SAFETY: `localtime_r` writes into a fully-owned `tm` and does not retain
    // the pointers; a null return just means we format an empty string.
    unsafe {
        let tt = t as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&tt, &mut tm).is_null() {
            return String::new();
        }
        format!(
            "{:04}-{:02}-{:02}{}{:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            sep,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}
