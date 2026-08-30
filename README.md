# cping-rs

A Rust port of **cping** (Concurrent Ping) by Willem A. Schreuder (AC0KQ),
originally a single-file C program (`../cping.c`, v2.4.0). Released under the
GNU GPL v2, same as the original.

It sends ICMP echo packets to a list of devices once per period and shows, for
each, a scrolling colour history, the approximate response time and the hop
count. A live parallel-traceroute view is available for the selected target.

## Building

```
make            # cargo build --release
make test
```

The binary is `target/release/cping-rs`.

### Installing

```
sudo make install                              # -> /usr/local/sbin/cping-rs
sudo make install INSTDIR=/usr/local/bin NAME=cping
```

`make install` copies the release binary to `$(INSTDIR)` (default
`/usr/local/sbin`, name `cping-rs`) and grants it the raw-socket privilege:
`setcap cap_net_raw=ep` on Linux, setuid root on macOS. `make uninstall` removes
it. `make help` lists every knob.

### Raspberry Pi GPIO buttons

The `-g` switch and the GPIO button support are behind a cargo feature that
only compiles on the Pi (it pulls in `rppal`):

```
cargo build --release --features gpio
```

## Running

Raw ICMP sockets need privilege, exactly as with the C version:

- **Linux:** run as root, or grant the capability once:
  `sudo setcap cap_net_raw=ep target/release/cping-rs`
  (add `cap_sys_rawio,cap_dac_override` as well when built with `--features gpio`).
- **macOS:** run with `sudo`.

```
cping-rs [-f cfg] [-o log] [-banrtxSv] [-p us] [-s sec] [-m size] [-N count] [-c ch]
```

Configuration file, command-line flags and key bindings are unchanged from the
original — see `../README`.

## Layout

| module        | corresponds to (`cping.c`)                              |
|---------------|--------------------------------------------------------|
| `ping.rs`     | `Ping` / `Stat`, `ByteTime`, ring-buffer helpers        |
| `icmp.rs`     | `checksum`, `ICMP`, `UnpackHeader`                      |
| `dnscache.rs` | `InitDNS` / `nslookup`                                  |
| `config.rs`   | `CheckOpt`, `ReadConfig`                                |
| `app.rs`      | the globals, `Bottom`, `Scroll`, `Resize`, `newsel`     |
| `net.rs`      | `InitSock`, `SendPing` thread, `Receive` thread         |
| `ui.rs`       | `Display`, `timeprint`, `DrawPing*`, `PrintHist`        |
| `output.rs`   | the `fout` log-file blocks                              |
| `gpio.rs`     | `#ifdef piGPIO` (`gpio`, `InitPIgpio`)                  |

## Notable implementation choices

- **TUI:** `ratatui` + `crossterm` instead of ncurses/PDCurses — no native
  curses dependency, and Windows would come almost for free if wanted.
- **Threads:** two `std::thread`s (send / receive) plus the input loop, mirroring
  the two C pthreads. Shared state lives in one `Arc<Mutex<App>>` rather than
  globals; immutable run parameters are a `Copy` `Params` struct.
- **Wire format:** ICMP id / sequence and the `f64` timestamp payload are still
  written in host byte order — both ends are the same machine, as in the C code.
- **`delt` clamping:** the Rust version also clamps `delt` at 0, avoiding a
  negative modulo that is technically undefined in the C original.
- The receive socket uses a 250 ms timeout so the thread can observe shutdown
  and the `0`-key socket reset.
