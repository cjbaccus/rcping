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

//! Raw ICMP socket plus the send and receive threads.
//!
//! Ported from `InitSock`, `SendPing` and `Receive` in `cping.c`. The two C
//! pthreads become two `std::thread`s; the C globals they poked at are reached
//! through `Arc<Mutex<App>>`.

use std::io;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::app::{App, Params};
use crate::icmp::{
    build_echo, unpack_header, ICMP_ECHOREPLY, ICMP_TIME_EXCEEDED, ICMP_UNREACH, TS_LEN,
};
use crate::ping::{byte_time, LATE_PING, LOST_PING, NSEC, P_TTL, T_TTL};
use crate::output;
use crate::util::now;

/// How long a blocked `recv_from` waits before looping, so the thread can
/// notice `run` going false and a socket swap on reset.
pub const RECV_TIMEOUT: Duration = Duration::from_millis(250);

/// Open a raw ICMPv4 socket (`socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)`).
pub fn make_socket() -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
}

/// Open the receive socket with the loop timeout applied.
pub fn make_recv_socket() -> io::Result<Socket> {
    let s = make_socket()?;
    s.set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok(s)
}

fn send_icmp(sock: &Mutex<Socket>, id: u16, seq: u16, ttl: u32, dst: &SockAddr, minsz: usize) {
    let pkt = build_echo(id, seq, minsz, now());
    if let Ok(s) = sock.lock() {
        let _ = s.set_ttl(ttl);
        let _ = s.send_to(&pkt, dst);
    }
}

/// Spawn the sender thread (`SendPing`).
pub fn spawn_sender(
    app: Arc<Mutex<App>>,
    params: Params,
    ntar: usize,
    sock: Arc<Mutex<Socket>>,
    run: Arc<AtomicBool>,
    show: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while run.load(Ordering::Relaxed) {
            let sel_addr;
            let target_addrs: Vec<SockAddr>;
            let seq_now: i32;
            {
                let mut a = app.lock().unwrap();
                a.total += 1;

                // Parallel traceroute bookkeeping.
                a.tseq += 1;
                if a.tseq > 65535 {
                    a.tseq = NSEC as i32;
                }
                a.nhop = T_TTL;
                for tr in a.traces.iter_mut() {
                    tr.dt = 0.0;
                    tr.ip = Ipv4Addr::UNSPECIFIED;
                    tr.ping.shift(&mut tr.stat);
                }
                sel_addr = a.targets[a.sel].sockaddr();

                // Log the previous group's ping times.
                if a.seq > 0 && a.out.is_some() {
                    let mut file = a.out.take().unwrap();
                    let _ = output::write_row(&mut file, &a.targets);
                    a.out = Some(file);
                }

                a.seq += 1;
                if a.seq > 65535 {
                    a.seq = NSEC as i32;
                }
                seq_now = a.seq;
                for t in a.targets.iter_mut() {
                    t.ping.shift(&mut t.stat);
                }
                target_addrs = a.targets.iter().map(|t| t.sockaddr()).collect();
            }

            // Send the traceroute sweep (TTL 1..=T_TTL).
            for k in 0..T_TTL {
                if !run.load(Ordering::Relaxed) {
                    return;
                }
                send_icmp(
                    &sock,
                    params.traceid,
                    (k + 1) as u16,
                    (k + 1) as u32,
                    &sel_addr,
                    params.minsz,
                );
                thread::sleep(Duration::from_micros(params.pus));
            }

            // Ping every target with the fixed TTL.
            for addr in &target_addrs {
                if !run.load(Ordering::Relaxed) {
                    return;
                }
                send_icmp(&sock, params.pingid, seq_now as u16, P_TTL, addr, params.minsz);
                thread::sleep(Duration::from_micros(params.pus));
            }

            // Pause until (roughly) the next second, then let the display update.
            let used = ntar as u64 * params.pus;
            thread::sleep(Duration::from_micros(950_000u64.saturating_sub(used)));
            show.store(true, Ordering::Relaxed);
            let extra = ((params.sbp - 1).max(0) as u64) * 1_000_000 + 50_000;
            thread::sleep(Duration::from_micros(extra));

            if params.num > 0 && seq_now >= params.num as i32 {
                run.store(false, Ordering::Relaxed);
            }
        }
    })
}

/// Spawn the receiver thread (`Receive`).
pub fn spawn_receiver(
    app: Arc<Mutex<App>>,
    params: Params,
    sock: Arc<Mutex<Socket>>,
    run: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [MaybeUninit::<u8>::uninit(); 8192];
        while run.load(Ordering::Relaxed) {
            let res = {
                let s = match sock.lock() {
                    Ok(s) => s,
                    Err(_) => break,
                };
                s.recv_from(&mut buf)
            };
            let (n, from) = match res {
                Ok(v) => v,
                Err(_) => continue, // timeout or transient error
            };
            if n == 0 {
                continue;
            }
            // SAFETY: `recv_from` reported `n` initialised bytes.
            let data: &[u8] =
                unsafe { &*(&buf[..n] as *const [MaybeUninit<u8>] as *const [u8]) };
            let src = match from.as_socket_ipv4() {
                Some(s) => *s.ip(),
                None => continue,
            };
            process(&app, &params, src, data);
        }
    })
}

/// Handle one received ICMP packet (the body of `Receive`'s loop).
fn process(app: &Mutex<App>, params: &Params, src: Ipv4Addr, data: &[u8]) {
    let h = match unpack_header(data) {
        Some(h) => h,
        None => return,
    };
    let payload = &data[h.len..];

    let mut a = app.lock().unwrap();
    let host = a.targets.iter().position(|t| t.ip == src);

    if h.rtp == ICMP_ECHOREPLY && payload.len() >= TS_LEN {
        let t0 = f64::from_ne_bytes(payload[..TS_LEN].try_into().unwrap());
        let dt = 1000.0 * (now() - t0);

        if h.rid == params.pingid {
            let hi = match host {
                Some(hi) => hi,
                None => return,
            };
            if h.rsq as i32 == a.seq {
                a.targets[hi].ttl = h.ttl;
                a.targets[hi].dt = dt;
                let bt = byte_time(dt);
                a.targets[hi].ping.set(0, bt);
                a.targets[hi].stat.update(dt);
            } else {
                a.targets[hi].stat.late += 1;
                let mut k = a.seq - h.rsq as i32;
                if k < 0 {
                    k += 65536 - NSEC as i32;
                }
                let delt = a.delt.max(0) as usize;
                if k > 0
                    && (k as usize) < NSEC
                    && a.targets[hi].ping.get(k as usize, delt) == LOST_PING
                {
                    a.targets[hi].ping.set(k as usize, LATE_PING);
                }
            }
        } else if h.rid == params.traceid && h.rsq > 0 && (h.rsq as usize) <= a.nhop {
            let idx = h.rsq as usize - 1;
            if (h.rsq as usize) < a.nhop {
                a.nhop = h.rsq as usize;
            }
            a.traces[idx].dt = dt;
            a.traces[idx].ip = src;
            let bt = byte_time(dt);
            a.traces[idx].ping.set(0, bt);
            a.traces[idx].stat.update(dt);
        }
    } else if h.rtp == ICMP_TIME_EXCEEDED {
        // The payload is the original packet we sent.
        let inner = match unpack_header(payload) {
            Some(x) => x,
            None => return,
        };
        let inner_payload = &payload[inner.len..];
        if inner_payload.len() < TS_LEN {
            return;
        }
        let t0 = f64::from_ne_bytes(inner_payload[..TS_LEN].try_into().unwrap());
        let dt = 1000.0 * (now() - t0);
        if inner.rid == params.traceid && inner.rsq > 0 && (inner.rsq as usize) <= a.nhop {
            let idx = inner.rsq as usize - 1;
            a.traces[idx].dt = dt;
            a.traces[idx].ip = src;
            let bt = byte_time(dt);
            a.traces[idx].ping.set(0, bt);
            a.traces[idx].stat.update(dt);
        }
    } else if h.rtp == ICMP_UNREACH {
        let inner = match unpack_header(payload) {
            Some(x) => x,
            None => return,
        };
        if inner.rid == params.traceid && inner.rsq > 0 && (inner.rsq as usize) < a.nhop {
            a.nhop = inner.rsq as usize;
            let idx = inner.rsq as usize - 1;
            a.traces[idx].dt = -1.0;
            a.traces[idx].ip = src;
        }
    }
}
