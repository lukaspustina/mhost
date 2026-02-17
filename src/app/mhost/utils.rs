// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::time::{Duration, Instant};

pub async fn time<T, F, E>(f: F) -> Result<(T, Duration), E>
where
    F: Future<Output = Result<T, E>>,
{
    let start_time = Instant::now();
    let res = f.await?;
    let run_time = Instant::now() - start_time;

    Ok((res, run_time))
}
