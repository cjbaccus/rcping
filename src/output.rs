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

//! Log-file writing (`-o`), ported from the `fout` blocks of `ReadConfig`,
//! `SendPing` and `main` in `cping.c`.

use std::fs::File;
use std::io::{self, Write};

use crate::app::{App, Target};
use crate::ping::LOST_PING;
use crate::util::{fmt_local, now};

/// Column header block, written once when the file is opened.
pub fn write_header(f: &mut File, targets: &[Target]) -> io::Result<()> {
    for (i, t) in targets.iter().enumerate() {
        if let Some(h) = &t.hdr {
            writeln!(f, "#{:20}{}", "", h)?;
        }
        writeln!(f, "#{:<3} {:<15} {}", i + 1, t.host, t.name)?;
    }
    writeln!(f, "#")?;
    write!(f, "#  Date      Time  ")?;
    for i in 0..targets.len() {
        write!(f, " {:6}", i + 1)?;
    }
    writeln!(f)?;
    Ok(())
}

/// One data row: timestamp followed by each target's last round-trip time.
pub fn write_row(f: &mut File, targets: &[Target]) -> io::Result<()> {
    write!(f, "{}", fmt_local(now() as i64, '-'))?;
    for t in targets {
        write!(f, " {:6.1}", t.dt)?;
    }
    writeln!(f)?;
    Ok(())
}

/// Summary block written at shutdown. The caller has already finalised the
/// lost counts (see [`finalize_lost`]).
pub fn write_footer(f: &mut File, app: &App) -> io::Result<()> {
    writeln!(f, "END Total pings {}", app.total)?;
    let t = &app.targets;
    let row = |f: &mut File, label: &str, cell: &dyn Fn(&Target) -> String| -> io::Result<()> {
        write!(f, "{label}")?;
        for x in t {
            write!(f, "{}", cell(x))?;
        }
        writeln!(f)
    };
    row(f, "Replies            ", &|x| format!(" {:6}", x.stat.n))?;
    row(f, "Lost               ", &|x| format!(" {:6}", x.stat.lost))?;
    row(f, "Late(>1s)          ", &|x| format!(" {:6}", x.stat.late))?;
    row(f, "Minimum            ", &|x| format!(" {:6.1}", x.stat.min))?;
    row(f, "Average            ", &|x| format!(" {:6.1}", x.stat.avg))?;
    row(f, "Maximum            ", &|x| format!(" {:6.1}", x.stat.max))?;
    row(f, "StdDev             ", &|x| format!(" {:6.1}", x.stat.std))?;
    Ok(())
}

/// Count the still-outstanding current ping as lost for each target, matching
/// the loop just before the summary in `main`.
pub fn finalize_lost(app: &mut App) {
    let delt = app.delt.max(0) as usize;
    for t in &mut app.targets {
        if t.ping.get(0, delt) == LOST_PING && t.stat.lost < 99999 {
            t.stat.lost += 1;
        }
    }
}
