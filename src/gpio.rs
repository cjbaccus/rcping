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

//! Raspberry Pi GPIO buttons (`#ifdef piGPIO` in `cping.c`).
//!
//! Only compiled with `--features gpio`. The four BCM pins are wired to
//! pull-ups and fire `swx` (1..=4) on a falling edge, matching `gpio()` /
//! `InitPIgpio()`.
#![cfg(feature = "gpio")]

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rppal::gpio::{Gpio, InputPin, Trigger};

/// BCM pin numbers, same as `int SW[]` in the C source.
const SW: [u8; 4] = [27, 23, 22, 17];

/// Debounce window (`if (t-swt<0.3) return;`).
const DEBOUNCE: Duration = Duration::from_millis(300);

/// Keeps the configured pins (and their interrupt threads) alive.
pub struct GpioGuard {
    _pins: Vec<InputPin>,
}

/// Configure the switch pins to publish into `swx`.
pub fn init(swx: Arc<AtomicU8>) -> Result<GpioGuard> {
    let gpio = Gpio::new()?;
    let mut pins = Vec::with_capacity(SW.len());
    for (i, bcm) in SW.iter().enumerate() {
        let mut pin = gpio.get(*bcm)?.into_input_pullup();
        let swx = swx.clone();
        let idx = (i + 1) as u8;
        pin.set_async_interrupt(Trigger::FallingEdge, Some(DEBOUNCE), move |_event| {
            swx.store(idx, Ordering::Relaxed);
        })?;
        pins.push(pin);
    }
    Ok(GpioGuard { _pins: pins })
}
