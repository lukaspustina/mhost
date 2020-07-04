use futures::stream::{self, StreamExt};
use futures::Future;
use log::{self, *};
use std::io::Write;
use tokio::task;
use trust_dns_resolver::config::*;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::proto::xfer::DnsRequestOptions;
use trust_dns_resolver::TokioAsyncResolver;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Async lookup algorithm -- no work is done
async fn lookup(i: usize) -> Result<Vec<Lookup>> {
    let config = match i {
        1 => ResolverConfig::google(),
        2 => ResolverConfig::cloudflare(),
        _ => ResolverConfig::quad9(),
    };
    let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default()).await?;
    debug!("Created {} Resolver.", i);

    let futures: Vec<_> = vec![
        RecordType::A,
        RecordType::A,
        RecordType::A,
        RecordType::AAAA,
        RecordType::AAAA,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::TXT,
        RecordType::TXT,
    ]
    .into_iter()
    .map(|x| make_lookup(i, &resolver, x))
    .collect();

    let mut res = Vec::new();
    let stream = stream::iter(futures);
    let mut buffered_stream = stream.buffer_unordered(2);
    while let Some(f) = buffered_stream.next().await {
        trace!("Received lookup {:?}", f);
        let f = f?;
        res.push(f)
    }

    Ok(res)
}

async fn make_lookup(i: usize, resolver: &TokioAsyncResolver, record_type: RecordType) -> Result<Lookup> {
    let lookup = resolver
        .lookup("www.example.com.", record_type, DnsRequestOptions::default())
        .await?;
    debug!("Received {} Lookup for record type {}.", i, record_type);

    Ok(lookup)
}

/// Create the futures -- no work is done
fn lookup_futures() -> Vec<impl Future<Output = Result<Vec<Lookup>>>> {
    let google = lookup(1);
    let cloudflare = lookup(2);
    let quad6 = lookup(3);

    vec![google, cloudflare, quad6]
}

/// Spawn the futures -- work is started
fn lookups_spawns(lookup_futures: Vec<impl Future<Output = Result<Vec<Lookup>>> + Send + 'static>) -> Vec<task::JoinHandle<Result<Vec<Lookup>>>> {
    lookup_futures.into_iter().map(task::spawn).collect()
}

/// Wait asyncly for the work to finish
async fn lookups(tasks: Vec<task::JoinHandle<Result<Vec<Lookup>>>>) -> Result<Vec<Lookup>> {
    let mut res = Vec::new();
    for t in tasks {
        let r = t.await??;
        res.push(r);
    }

    Ok(res.into_iter().flatten().collect())
}

fn main() -> Result<()> {
    let start = std::time::Instant::now();
    env_logger::Builder::from_default_env()
        .format(move |buf, rec| {
            let t = start.elapsed().as_secs_f32();
            let thread_id_string = format!("{:?}", std::thread::current().id());
            let thread_id = &thread_id_string[9..thread_id_string.len()-1];
            writeln!(buf, "{:.03} [{:5}] ({:}) - {}", t, rec.level(), thread_id, rec.args())
        })
        .init();

    let mut rt = tokio::runtime::Runtime::new()
        .expect("Failed to create runtime.");

    rt.block_on(async {
        let futures = lookup_futures();
        let tasks = lookups_spawns(futures);
        let lookups = lookups(tasks).await;
        match lookups {
            //Ok(lookup) => info!("Lookup: {:#?}", lookup),
            Ok(_) => info!("Done."),
            Err(e) => error!("An error occurred: {}", e),
        }
    });

    Ok(())
}