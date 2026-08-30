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

//! Screen rendering, ported from `Display`, `timeprint`, `DrawPing`,
//! `DrawPingRow` and `PrintHist` in `cping.c`.
//!
//! The C code drew straight onto the curses screen with `printw`/`addch` and
//! colour pairs. Here each frame is built as a `Vec<Line>` of styled `Span`s
//! and handed to a ratatui `Paragraph`; the column arithmetic is kept
//! identical.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::app::{App, Params};
use crate::dnscache::DnsCache;
use crate::ping::{Ping, LATE_PING, LOST_PING, NO_PING, NSEC, VER};
use crate::util::{fmt_local, now};

/// Key bindings shown on the help screen (`const char* help` in `cping.c`).
const HELP: &str = "\
PgUp   Scroll up
PgDn   Scroll down
  ^    Select previous router
  v    Select next router
 <-    Reverse time a second
 ->    Advance time a second
  -    Reverse time a minute
  +    Advance time a minute
 End   Current time
  0    Reset stats
ENTER  Traceroute to router
 ESC   Return to ping screen
  i    Invert colors
  r    Reverse direction
  t    Toggle time statistics
  S    Toggle sound for all
  s    Toggle sound for selected
  a    Toggle address
  n    Toggle hop count
  c    Toggle character
  h    Help
  q    Quit program";

/// A rendered frame.
pub struct Screen {
    pub lines: Vec<Line<'static>>,
    /// Ring the terminal bell after drawing.
    pub bell: bool,
    /// Base style (colour pair 1) for the whole area.
    pub base: Style,
}

/// curses colour pair → ratatui style. Pair 1 is the normal text colour,
/// 2..=5 are cyan/green/yellow/red on the same background (`SetColor`).
fn pair(white: bool, p: u8) -> Style {
    let bg = if white { Color::White } else { Color::Black };
    let fg = match (white, p) {
        (true, 1) => Color::Black,
        (false, 1) => Color::White,
        (_, 2) => Color::Cyan,
        (_, 3) => Color::Green,
        (_, 4) => Color::Yellow,
        _ => Color::Red,
    };
    Style::default().fg(fg).bg(bg)
}

/// Incrementally built line that coalesces runs of same-styled text.
struct Row {
    spans: Vec<Span<'static>>,
}

impl Row {
    fn new() -> Self {
        Row { spans: Vec::new() }
    }

    fn push(&mut self, s: impl Into<String>, style: Style) {
        let s = s.into();
        if s.is_empty() {
            return;
        }
        if let Some(last) = self.spans.last_mut() {
            if last.style == style {
                last.content.to_mut().push_str(&s);
                return;
            }
        }
        self.spans.push(Span::styled(s, style));
    }

    fn ch(&mut self, c: char, style: Style) {
        if let Some(last) = self.spans.last_mut() {
            if last.style == style {
                last.content.to_mut().push(c);
                return;
            }
        }
        self.spans.push(Span::styled(c.to_string(), style));
    }

    fn into_line(self) -> Line<'static> {
        Line::from(self.spans)
    }
}

/// Write `s` into exactly `width` columns, padding with `fill` and truncating
/// (`for (l=0;l<width;l++) addch(*ch?*ch++:fill)`).
fn push_fixed(row: &mut Row, s: &str, width: usize, fill: char, style: Style) {
    let mut n = 0;
    for c in s.chars() {
        if n >= width {
            break;
        }
        row.ch(c, style);
        n += 1;
    }
    while n < width {
        row.ch(fill, style);
        n += 1;
    }
}

fn hist_char_r2l(l: i64) -> char {
    if l % 10 == 0 {
        '0'
    } else if l > 10 && (l - 1) % 10 == 0 {
        (b'0' + ((l % 100) / 10) as u8) as char
    } else if l > 100 && (l - 2) % 10 == 0 {
        (b'0' + (l / 100) as u8) as char
    } else {
        ' '
    }
}

fn hist_char_l2r(l: i64) -> char {
    if l % 10 == 0 {
        '0'
    } else if l > 8 && (l + 1) % 10 == 0 {
        (b'0' + (((l + 1) % 100) / 10) as u8) as char
    } else if l > 97 && (l + 2) % 10 == 0 {
        (b'0' + ((l + 2) / 100) as u8) as char
    } else {
        ' '
    }
}

/// The tick ruler above a ping row (`PrintHist`).
fn print_hist(r2l: bool, n: usize) -> String {
    let mut s = String::with_capacity(n);
    if r2l {
        for l in (0..n).rev() {
            s.push(hist_char_r2l(l as i64));
        }
    } else {
        for l in 0..n {
            s.push(hist_char_l2r(l as i64));
        }
    }
    s
}

/// One history cell (`DrawPing`).
fn draw_ping(row: &mut Row, a: &App, ping: &Ping, l: usize, delt: usize) {
    let ch = ping.get(l, delt);
    if ch == NO_PING {
        row.ch('-', pair(a.white, 1));
    } else if ch == LOST_PING || ch == LATE_PING {
        let st = pair(a.white, 5).add_modifier(Modifier::BOLD);
        row.ch(if ch == LOST_PING { 'X' } else { '+' }, st);
    } else {
        let color = (ch >> 4) + 2;
        let st = pair(a.white, color);
        if a.ich == 3 {
            row.ch(
                (b'0' + (ch & 0xF)) as char,
                st.add_modifier(Modifier::BOLD),
            );
        } else if let Some(pc) = a.pch {
            row.ch(pc, st);
        } else if a.ich == 2 {
            row.ch('*', st);
        } else if a.ich == 1 {
            row.ch('\u{2588}', st); // ACS_BLOCK
        } else {
            row.ch('\u{25C6}', st); // ACS_DIAMOND
        }
    }
}

/// A full history row, honouring the scroll direction (`DrawPingRow`).
fn draw_ping_row(row: &mut Row, a: &App, ping: &Ping, n: usize, delt: usize) {
    if a.r2l {
        for l in (0..n).rev() {
            draw_ping(row, a, ping, l, delt);
        }
    } else {
        for l in 0..n {
            draw_ping(row, a, ping, l, delt);
        }
    }
}

/// The status/clock line (`timeprint`).
fn timeprint(a: &App, params: &Params) -> Line<'static> {
    let mut row = Row::new();
    let p1 = pair(a.white, 1);

    let t = now() as i64 - a.delt;
    let mut head = fmt_local(t, ' ');
    if a.delt != 0 {
        head.push_str(&format!(" dt={}", a.delt));
    }
    head.push_str(&format!(
        "   #{}  Period {}s Ping time",
        a.seq, params.sbp
    ));
    row.push(head, p1);

    if a.ich == 3 {
        let b = Modifier::BOLD;
        row.push(" x1", pair(a.white, 2).add_modifier(b));
        row.push(" x10", pair(a.white, 3).add_modifier(b));
        row.push(" x100", pair(a.white, 4).add_modifier(b));
        row.push(" x1000", pair(a.white, 5).add_modifier(b));
    } else {
        row.push(" <10", pair(a.white, 2));
        row.push(" 10-99", pair(a.white, 3));
        row.push(" 100-999", pair(a.white, 4));
        row.push(" >1000", pair(a.white, 5));
    }
    if a.silent {
        row.push(" SILENT", pair(a.white, 5));
    }
    row.into_line()
}

/// Build the next frame. Mutates `a.delt` (history-review auto-advance) and
/// `a.nhop` (trailing-hop trim), exactly as `Display` did.
pub fn render(a: &mut App, dns: &mut DnsCache, params: &Params, new: bool) -> Screen {
    // Stop the window advancing once it reaches the end of the buffer.
    if new && a.delt > 0 {
        a.delt += 1;
    }
    let cap = (NSEC as i64 - a.nping - 3).max(0);
    if a.delt > cap {
        a.delt = cap;
    }
    if a.delt < 0 {
        a.delt = 0;
    }

    if a.mode > 0 {
        while a.nhop > 1
            && a.traces[a.nhop - 1].ip.is_unspecified()
            && a.traces[a.nhop - 2].ip.is_unspecified()
        {
            a.nhop -= 1;
        }
    }

    let base = pair(a.white, 1);
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut bell = false;

    if a.mode < 0 {
        help_screen(a, &mut lines);
    } else if a.mode > 0 {
        let nhop = a.nhop;
        let mut hop_names: Vec<(String, String)> = Vec::with_capacity(nhop);
        for k in 0..nhop {
            let (addr, fqdn) = dns.lookup(a.traces[k].ip);
            hop_names.push((fqdn.to_string(), addr.to_string()));
        }
        trace_screen(a, params, &hop_names, &mut lines, &mut bell);
    } else {
        ping_screen(a, params, &mut lines, &mut bell);
    }

    Screen {
        lines,
        bell: new && bell,
        base,
    }
}

fn help_screen(a: &App, lines: &mut Vec<Line<'static>>) {
    let p1 = pair(a.white, 1);
    let pb = p1.add_modifier(Modifier::BOLD);
    lines.push(Line::styled(format!("cping version {VER}"), pb));
    lines.push(Line::styled(" Key   Function".to_string(), pb));
    for l in HELP.lines() {
        lines.push(Line::styled(l.to_string(), p1));
    }
}

fn ping_screen(
    a: &App,
    params: &Params,
    lines: &mut Vec<Line<'static>>,
    bell: &mut bool,
) {
    let ntar = a.targets.len();
    let hgt = a.hgt as usize;
    let nping = a.nping.max(0) as usize;
    let p1 = pair(a.white, 1);
    let pb = p1.add_modifier(Modifier::BOLD);
    let delt = a.delt.max(0) as usize;

    let mut i = 1usize;
    if ntar + a.nhdr + 1 < hgt || hgt > 20 {
        lines.push(timeprint(a, params));
        i += 1;
    }

    // Column header.
    let mut hr = Row::new();
    let mut label = String::from("Target");
    for _ in 6..a.nwid {
        label.push(' ');
    }
    hr.push(label, pb);
    if a.showip {
        let mut addr = String::from(" Address");
        for _ in 7..a.awid {
            addr.push(' ');
        }
        hr.push(addr, pb);
    }
    hr.push(print_hist(a.r2l, nping), pb);
    hr.push("   ms", pb);
    if a.hop {
        hr.push(" hop", pb);
    }
    if a.stat {
        hr.push("   min   avg   max lost", pb);
    }
    lines.push(hr.into_line());

    for k in a.top..ntar {
        if i >= hgt {
            break;
        }
        i += 1;
        if let Some(hdr) = a.targets[k].hdr.clone() {
            lines.push(Line::styled(hdr, pb));
            i += 1;
            if i > hgt {
                break;
            }
        }

        let t = &a.targets[k];
        let name_style = if k == a.sel && t.silent {
            pair(a.white, 4)
        } else if t.silent {
            pair(a.white, 5)
        } else if k == a.sel {
            pair(a.white, 3)
        } else {
            pair(a.white, 1)
        };

        let mut row = Row::new();
        push_fixed(&mut row, &t.name, a.nwid, '.', name_style);
        if a.showip {
            row.ch(' ', name_style);
            push_fixed(&mut row, &t.host, a.awid, '.', name_style);
        }
        draw_ping_row(&mut row, a, &t.ping, nping, delt);

        if t.dt < 0.0 {
            row.push(" -----", p1);
        } else {
            row.push(format!(" {:5.1}", t.dt), p1);
        }
        if a.hop {
            let ttl0: i32 = if t.ttl > 128 {
                256
            } else if t.ttl > 64 {
                128
            } else {
                64
            };
            let l = ttl0 + 1 - t.ttl as i32;
            if t.dt < 0.0 || l < 0 {
                row.push(" --", p1);
            } else {
                row.push(format!(" {:2}", l), p1);
            }
        }
        if a.stat {
            row.push(
                format!(
                    "{:6.1}{:6.1}{:6.1}{:5}",
                    t.stat.min, t.stat.avg, t.stat.max, t.stat.lost
                ),
                p1,
            );
        }
        lines.push(row.into_line());
    }

    if !a.silent {
        for k in 0..ntar {
            if a.seq > 1
                && a.targets[k].ping.get(0, delt) == LOST_PING
                && !a.targets[k].silent
            {
                *bell = true;
            }
        }
    }
}

fn trace_screen(
    a: &App,
    params: &Params,
    hop_names: &[(String, String)],
    lines: &mut Vec<Line<'static>>,
    bell: &mut bool,
) {
    let hgt = a.hgt as usize;
    let wid = a.wid as i64;
    let nhop = a.nhop;
    let p1 = pair(a.white, 1);
    let pb = p1.add_modifier(Modifier::BOLD);
    let delt = a.delt.max(0) as usize;

    if nhop + 3 < hgt {
        lines.push(timeprint(a, params));
    }
    lines.push(Line::styled(
        format!("Traceroute to {}", a.targets[a.sel].name),
        pb,
    ));
    lines.push(Line::styled(String::new(), p1));

    let mut len: i64 = 5;
    let mut lan: i64 = 4;
    for (fqdn, addr) in hop_names {
        len = len.max(fqdn.len() as i64);
        lan = lan.max(addr.len() as i64);
    }
    if len + lan + 12 > wid {
        len = wid - 12 - lan;
    }
    let mut ntrac = wid - 13 - len - lan;
    if a.stat {
        ntrac -= 23;
    }
    if ntrac > NSEC as i64 {
        ntrac = NSEC as i64;
    }
    let len_u = len.max(0) as usize;
    let lan_u = lan.max(0) as usize;
    let ntrac_u = ntrac.max(0) as usize;

    // Header.
    let mut hr = Row::new();
    let mut h = String::from("Hop Host");
    for _ in 0..len_u {
        h.push(' ');
    }
    h.push_str(" IP");
    for _ in 5..lan_u {
        h.push(' ');
    }
    hr.push(h, pb);
    hr.push(print_hist(a.r2l, ntrac_u), pb);
    hr.push("    ms", pb);
    if a.stat {
        hr.push("   min   avg   max lost", pb);
    }
    lines.push(hr.into_line());

    let m = nhop.min(hgt.saturating_sub(3));
    #[allow(clippy::needless_range_loop)]
    for k in 0..m {
        let tr = &a.traces[k];
        let mut row = Row::new();
        row.push(format!("{:3} ", k + 1), p1);
        push_fixed(&mut row, &hop_names[k].0, len_u + 1, ' ', p1);
        push_fixed(&mut row, &hop_names[k].1, lan_u + 1, ' ', p1);
        draw_ping_row(&mut row, a, &tr.ping, ntrac_u, delt);
        if tr.dt < 0.0 {
            row.push(" unrch", p1);
        } else {
            row.push(format!(" {:5.1}", tr.dt), p1);
        }
        if a.stat {
            row.push(
                format!(
                    "{:6.1}{:6.1}{:6.1}{:5}",
                    tr.stat.min, tr.stat.avg, tr.stat.max, tr.stat.lost
                ),
                p1,
            );
        }
        lines.push(row.into_line());
    }

    if !a.silent && !a.targets[a.sel].silent {
        for k in 0..nhop {
            if a.traces[k].dt < 0.0 {
                *bell = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{new_traces, App, Params, Target};
    use crate::ping::{byte_time, Ping, Stat};
    use std::net::Ipv4Addr;

    fn plain(s: &Line) -> String {
        s.spans.iter().map(|sp| sp.content.as_ref()).collect()
    }

    fn target(name: &str, ip: [u8; 4]) -> Target {
        Target {
            hdr: None,
            name: name.to_string(),
            host: String::new(),
            silent: false,
            dt: -1.0,
            ping: Ping::new(),
            stat: Stat::new(),
            ttl: 0,
            ip: Ipv4Addr::from(ip),
        }
    }

    fn app(targets: Vec<Target>) -> App {
        let mut a = App {
            targets,
            traces: new_traces(),
            nhdr: 0,
            nwid: 8,
            awid: 6,
            seq: 5,
            tseq: 0,
            nhop: 0,
            mode: 0,
            delt: 0,
            sel: 0,
            top: 0,
            white: true,
            r2l: true,
            hop: true,
            stat: false,
            showip: false,
            silent: false,
            ich: 0,
            pch: None,
            wid: 0,
            hgt: 0,
            nping: 0,
            total: 0,
            out: None,
        };
        a.resize(120, 40);
        a
    }

    fn params() -> Params {
        Params {
            minsz: 0,
            pus: 1000,
            sbp: 1,
            num: 0,
            pingid: 100,
            traceid: 101,
        }
    }

    #[test]
    fn ping_screen_has_header_and_rows() {
        let mut a = app(vec![target("Alpha", [1, 1, 1, 1]), target("Bravo", [2, 2, 2, 2])]);
        a.targets[0].dt = 12.3;
        a.targets[0].ping.set(0, byte_time(12.3));
        let mut dns = DnsCache::new();
        let s = render(&mut a, &mut dns, &params(), true);
        let text: Vec<String> = s.lines.iter().map(plain).collect();
        assert!(text.iter().any(|l| l.starts_with("Target")));
        assert!(text.iter().any(|l| l.contains("Alpha")));
        assert!(text.iter().any(|l| l.contains("Bravo")));
        // Alpha has a fresh reply, so its row shows the formatted time.
        assert!(text.iter().any(|l| l.contains("Alpha") && l.contains("12.3")));
    }

    #[test]
    fn help_screen_lists_keys() {
        let mut a = app(vec![target("Alpha", [1, 1, 1, 1])]);
        a.mode = -1;
        let mut dns = DnsCache::new();
        let s = render(&mut a, &mut dns, &params(), false);
        let text: Vec<String> = s.lines.iter().map(plain).collect();
        assert!(text[0].contains(VER));
        assert!(text.iter().any(|l| l.contains("Quit program")));
    }

    #[test]
    fn trace_screen_renders_selected_target() {
        let mut a = app(vec![target("Alpha", [1, 1, 1, 1])]);
        a.mode = 1;
        a.nhop = 2;
        a.traces[0].ip = Ipv4Addr::new(10, 0, 0, 1);
        a.traces[0].dt = 4.2;
        let mut dns = DnsCache::new();
        let s = render(&mut a, &mut dns, &params(), false);
        let text: Vec<String> = s.lines.iter().map(plain).collect();
        assert!(text.iter().any(|l| l.contains("Traceroute to Alpha")));
        assert!(text.iter().any(|l| l.contains("4.2")));
    }
}
