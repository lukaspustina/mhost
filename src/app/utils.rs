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
