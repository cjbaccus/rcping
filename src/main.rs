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
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

//! cping — concurrent ping / traceroute TUI.
//!
//! A Rust port of `cping.c` by Willem A. Schreuder (GPLv2). The program pings a
//! list of targets once per period, shows a scrolling colour history for each,
//! and offers a live parallel-traceroute view for the selected target.

mod app;
mod config;
mod dnscache;
mod gpio;
mod icmp;
mod net;
mod output;
mod ping;
mod ui;
mod util;

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, size, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::widgets::Paragraph;
use ratatui::Terminal;
use socket2::Socket;

use app::{new_traces, App, Params};
use config::{read_config, Options};
use dnscache::DnsCache;
use ping::{T_TTL, VER};

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

/// Command-line options (`OPTSTR` / `getopt` loop in `cping.c`).
#[derive(Parser)]
#[command(
    name = "cping",
    version = VER,
    disable_version_flag = true,
    about = "Concurrent ping — Rust port of cping"
)]
struct Args {
    /// config file [default cping.cfg or /etc/cping.cfg]
    #[arg(short = 'f')]
    file: Option<String>,
    /// white lettering on black background
    #[arg(short = 'b')]
    black: bool,
    /// show address in ping table
    #[arg(short = 'a')]
    address: bool,
    /// no hops on ping table
    #[arg(short = 'n')]
    no_hop: bool,
    /// scroll pings left to right
    #[arg(short = 'r')]
    reverse: bool,
    /// microseconds between pings [default 1000]
    #[arg(short = 'p')]
    pus: Option<String>,
    /// output file
    #[arg(short = 'o')]
    out: Option<String>,
    /// stop after this many pings
    #[arg(short = 'N')]
    num: Option<String>,
    /// seconds between ping [1-5]
    #[arg(short = 's')]
    sbp: Option<String>,
    /// minimum ICMP packet size
    #[arg(short = 'm')]
    minsz: Option<String>,
    /// start silent
    #[arg(short = 'S')]
    silent: bool,
    /// show numeric ping character
    #[arg(short = 'x')]
    numeric: bool,
    /// show ping time stats
    #[arg(short = 't')]
    stat: bool,
    /// ping character
    #[arg(short = 'c')]
    pch: Option<String>,
    /// enable Raspberry Pi GPIO buttons
    #[arg(short = 'g')]
    gpio: bool,
    /// show version
    #[arg(short = 'v')]
    show_version: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.show_version {
        println!("cping version {VER}");
        return Ok(());
    }

    // Read config (which may itself set options), then let the command line win.
    let mut opts = Options::default();
    let files = match &args.file {
        Some(f) => vec![f.clone()],
        None => vec!["cping.cfg".to_string(), "/etc/cping.cfg".to_string()],
    };
    let cfg = read_config(&files, &mut opts)?;

    if args.black {
        opts.check_opt('b', "")?;
    }
    if args.no_hop {
        opts.check_opt('n', "")?;
    }
    if args.reverse {
        opts.check_opt('r', "")?;
    }
    if args.address {
        opts.check_opt('a', "")?;
    }
    if args.numeric {
        opts.check_opt('x', "")?;
    }
    if args.stat {
        opts.check_opt('t', "")?;
    }
    if args.silent {
        opts.check_opt('S', "")?;
    }
    if let Some(v) = &args.minsz {
        opts.check_opt('m', v)?;
    }
    if let Some(v) = &args.pus {
        opts.check_opt('p', v)?;
    }
    if let Some(v) = &args.sbp {
        opts.check_opt('s', v)?;
    }
    if let Some(v) = &args.num {
        opts.check_opt('N', v)?;
    }
    if let Some(v) = &args.pch {
        opts.check_opt('c', v)?;
    }
    if let Some(v) = &args.out {
        opts.check_opt('o', v)?;
    }

    let ntar = cfg.targets.len();
    if opts.pus.saturating_mul(ntar as u64 + T_TTL as u64) > 950_000 {
        bail!("Pause length exceeds one second");
    }

    let out = match &opts.out_path {
        Some(p) => {
            let mut f = std::fs::File::create(p)
                .with_context(|| format!("Cannot open output file {p}"))?;
            output::write_header(&mut f, &cfg.targets)?;
            Some(f)
        }
        None => None,
    };

    let pid = std::process::id();
    let pingid = (((pid & 0x7FFF) << 1) & 0xFFFF) as u16;
    let traceid = pingid | 1;
    let params = Params {
        minsz: opts.minsz,
        pus: opts.pus,
        sbp: opts.sbp,
        num: opts.num,
        pingid,
        traceid,
    };

    let app = Arc::new(Mutex::new(App {
        targets: cfg.targets,
        traces: new_traces(),
        nhdr: cfg.nhdr,
        nwid: cfg.nwid,
        awid: cfg.awid,
        seq: 0,
        tseq: 0,
        nhop: 0,
        mode: 0,
        delt: 0,
        sel: 0,
        top: 0,
        white: opts.white,
        r2l: opts.r2l,
        hop: opts.hop,
        stat: opts.stat,
        showip: opts.showip,
        silent: opts.silent,
        ich: opts.ich,
        pch: opts.pch,
        wid: 0,
        hgt: 0,
        nping: 0,
        total: 0,
        out,
    }));

    let sock_err = "Cannot open ICMP socket (needs root / CAP_NET_RAW, or run with sudo)";
    let send_sock = Arc::new(Mutex::new(net::make_socket().context(sock_err)?));
    let recv_sock = Arc::new(Mutex::new(net::make_recv_socket().context(sock_err)?));

    let run = Arc::new(AtomicBool::new(true));
    let show = Arc::new(AtomicBool::new(false));
    let swx = Arc::new(AtomicU8::new(0));

    #[cfg(feature = "gpio")]
    let _gpio_guard = if args.gpio {
        Some(gpio::init(swx.clone()).context("Cannot initialize GPIO")?)
    } else {
        None
    };
    #[cfg(not(feature = "gpio"))]
    if args.gpio {
        bail!("Compiled without GPIO support (rebuild with --features gpio)");
    }

    install_panic_hook();
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, Hide)?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let (w, h) = size().unwrap_or((80, 24));
    app.lock().unwrap().resize(w, h);

    let rx = net::spawn_receiver(app.clone(), params, recv_sock.clone(), run.clone());
    let tx = net::spawn_sender(
        app.clone(),
        params,
        ntar,
        send_sock.clone(),
        run.clone(),
        show.clone(),
    );

    let res = run_loop(
        &mut term, &app, &send_sock, &recv_sock, &params, &run, &show, &swx,
    );

    // Restore the terminal no matter how the loop ended.
    run.store(false, Ordering::Relaxed);
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
    let _ = term.show_cursor();

    let _ = tx.join();
    let _ = rx.join();

    // Log summary (`if (fout)` block at the end of `main`).
    {
        let mut a = app.lock().unwrap();
        if a.out.is_some() {
            output::finalize_lost(&mut a);
            let mut f = a.out.take().unwrap();
            output::write_footer(&mut f, &a)?;
        }
    }

    res
}

#[allow(clippy::too_many_arguments)]
fn run_loop(
    term: &mut Tui,
    app: &Mutex<App>,
    send_sock: &Mutex<Socket>,
    recv_sock: &Mutex<Socket>,
    params: &Params,
    run: &AtomicBool,
    show: &AtomicBool,
    swx: &AtomicU8,
) -> Result<()> {
    let mut dns = DnsCache::new();
    draw(term, app, &mut dns, params, false)?;

    while run.load(Ordering::Relaxed) {
        // GPIO switches (`swx` in `cping.c`).
        let sw = swx.swap(0, Ordering::Relaxed);
        if sw != 0 {
            {
                let mut a = app.lock().unwrap();
                match sw {
                    1 => a.mode = if a.mode != 0 { 0 } else { 1 },
                    2 => a.newsel(-1),
                    3 => a.newsel(1),
                    4 => {
                        a.showip = !a.showip;
                        let (w, h) = (a.wid, a.hgt);
                        a.resize(w, h);
                    }
                    _ => {}
                }
            }
            draw(term, app, &mut dns, params, false)?;
            continue;
        }

        if event::poll(Duration::from_millis(1))? {
            match event::read()? {
                Event::Key(k)
                    if k.kind == KeyEventKind::Press || k.kind == KeyEventKind::Repeat =>
                {
                    if handle_key(k.code, app, send_sock, recv_sock, run)? {
                        draw(term, app, &mut dns, params, false)?;
                    }
                }
                Event::Resize(w, h) => {
                    app.lock().unwrap().resize(w, h);
                    draw(term, app, &mut dns, params, false)?;
                }
                _ => {}
            }
        } else if show.swap(false, Ordering::Relaxed) {
            draw(term, app, &mut dns, params, true)?;
        }
    }
    Ok(())
}

/// Handle one key. Returns `true` when the screen should be redrawn now
/// (a plain `Display(0)` in the C key loop).
fn handle_key(
    code: KeyCode,
    app: &Mutex<App>,
    send_sock: &Mutex<Socket>,
    recv_sock: &Mutex<Socket>,
    run: &AtomicBool,
) -> Result<bool> {
    use KeyCode::*;
    let mut a = app.lock().unwrap();
    match code {
        Char('q') => {
            run.store(false, Ordering::Relaxed);
            return Ok(false);
        }
        Left => a.delt += 1,
        Right => {
            if a.delt > 0 {
                a.delt -= 1;
            }
        }
        Char('-') => a.delt += 60,
        Char('+') => {
            a.delt -= 60;
            if a.delt < 0 {
                a.delt = 0;
            }
        }
        End => a.delt = 0,
        PageDown => a.scroll(1),
        PageUp => a.scroll(-1),
        Up => a.newsel(-1),
        Down => a.newsel(1),
        Enter => a.mode = if a.mode != 0 { 0 } else { 1 },
        Esc => a.mode = 0,
        Char('n') => {
            a.hop = !a.hop;
            let (w, h) = (a.wid, a.hgt);
            a.resize(w, h);
        }
        Char('i') => a.white = !a.white,
        Char('r') => a.r2l = !a.r2l,
        Char('a') => {
            a.showip = !a.showip;
            let (w, h) = (a.wid, a.hgt);
            a.resize(w, h);
        }
        Char('t') => {
            a.stat = !a.stat;
            let (w, h) = (a.wid, a.hgt);
            a.resize(w, h);
        }
        Char('S') => a.silent = !a.silent,
        Char('s') => {
            let s = a.sel;
            a.targets[s].silent = !a.targets[s].silent;
        }
        Char('h') => a.mode = -1,
        Char('c') => {
            a.ich = (a.ich + 1) % 4;
            return Ok(false);
        }
        Char('0') => {
            drop(a);
            *send_sock.lock().unwrap() =
                net::make_socket().context("reset: cannot open ICMP socket")?;
            *recv_sock.lock().unwrap() =
                net::make_recv_socket().context("reset: cannot open ICMP socket")?;
            app.lock().unwrap().reset_stats();
            return Ok(true);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn draw(
    term: &mut Tui,
    app: &Mutex<App>,
    dns: &mut DnsCache,
    params: &Params,
    new: bool,
) -> Result<()> {
    let (lines, base, bell) = {
        let mut a = app.lock().unwrap();
        let s = ui::render(&mut a, dns, params, new);
        (s.lines, s.base, s.bell)
    };
    term.draw(|f| {
        let area = f.area();
        f.render_widget(Paragraph::new(lines).style(base), area);
    })?;
    if bell {
        let mut o = io::stdout();
        let _ = o.write_all(b"\x07");
        let _ = o.flush();
    }
    Ok(())
}

/// Restore the terminal if a panic unwinds through the raw-mode section.
fn install_panic_hook() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        hook(info);
    }));
}
