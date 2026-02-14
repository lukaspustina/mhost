// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

use yansi::{Color, Style};

static ASCII_MODE: AtomicBool = AtomicBool::new(false);

pub fn ascii_mode() {
    ASCII_MODE.store(true, SeqCst);
}

pub fn no_color_mode() {
    yansi::disable();
}

pub static ATTENTION: Style = Style::new().fg(Color::Yellow).bold();
pub static ERROR: Style = Style::new().fg(Color::Red).bold();
pub static EMPH: Style = Style::new().fg(Color::White).bold();
pub static OK: Style = Style::new().fg(Color::Green).bold();

pub fn attention_prefix() -> &'static str {
    if ASCII_MODE.load(SeqCst) { "!" } else { "⚠︎" }
}

pub fn caption_prefix() -> &'static str {
    if ASCII_MODE.load(SeqCst) { ">" } else { "▶︎" }
}

pub fn error_prefix() -> &'static str {
    if ASCII_MODE.load(SeqCst) { "!" } else { "⚡︎" }
}

pub fn info_prefix() -> &'static str {
    if ASCII_MODE.load(SeqCst) { "-" } else { "▸" }
}

pub fn itemization_prefix() -> &'static str {
    if ASCII_MODE.load(SeqCst) { "*" } else { "∙" }
}

pub fn finished_prefix() -> &'static str {
    if ASCII_MODE.load(SeqCst) { "+" } else { "❖" }
}

pub fn ok_prefix() -> &'static str {
    if ASCII_MODE.load(SeqCst) { "=" } else { "✓" }
}
