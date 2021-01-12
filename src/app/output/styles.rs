// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

use lazy_static::lazy_static;
use yansi::{Color, Style};

static ASCII_MODE: AtomicBool = AtomicBool::new(false);

pub fn ascii_mode() {
    ASCII_MODE.store(true, SeqCst);
}

pub fn no_color_mode() {
    yansi::Paint::disable();
}

lazy_static! {
    pub static ref ATTENTION: Style = Style::new(Color::Yellow).bold();
    pub static ref ERROR: Style = Style::new(Color::Red).bold();
    pub static ref EMPH: Style = Style::new(Color::White).bold();
    pub static ref OK: Style = Style::new(Color::Green).bold();
    pub static ref ATTENTION_PREFIX: String = (if ASCII_MODE.load(SeqCst) { "!" } else { "⚠︎" }).to_string();
    pub static ref CAPTION_PREFIX: String = (if ASCII_MODE.load(SeqCst) { ">" } else { "▶︎" }).to_string();
    pub static ref ERROR_PREFIX: String = (if ASCII_MODE.load(SeqCst) { "!" } else { "⚡︎" }).to_string();
    pub static ref INFO_PREFIX: String = (if ASCII_MODE.load(SeqCst) { "-" } else { "▸" }).to_string();
    pub static ref ITEMAZATION_PREFIX: String = (if ASCII_MODE.load(SeqCst) { "*" } else { "∙" }).to_string();
    pub static ref FINISHED_PREFIX: String = (if ASCII_MODE.load(SeqCst) { "+" } else { "❖" }).to_string();
    pub static ref OK_PREFIX: String = (if ASCII_MODE.load(SeqCst) { "=" } else { "✓" }).to_string();
}
