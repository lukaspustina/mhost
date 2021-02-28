// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Various helpers for serialization and concurrent execution control.

pub mod buffer_unordered_with_breaker;
pub(crate) mod deserialize;
pub(crate) mod serialize;
#[cfg(test)]
pub(crate) mod tests;
