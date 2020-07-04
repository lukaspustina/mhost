use futures::stream::{self, StreamExt};
use log::{self, *};
use std::io::Write;
use std::sync::Arc;
use tokio::task;
use trust_dns_resolver::config::*;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::proto::xfer::DnsRequestOptions;
use trust_dns_resolver::TokioAsyncResolver;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub struct MyResolver {
    inner: Arc<TokioAsyncResolver>,
    name: String,
}

impl MyResolver {
    pub async fn new(i: usize) -> Result<Self> {
        let config = match i {
            1 => ResolverConfig::google(),
            2 => ResolverConfig::cloudflare(),
            _ => ResolverConfig::quad9(),
        };
        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default()).await?;
        debug!("Created {} Resolver.", i);

        Ok(MyResolver {
            inner: Arc::new(resolver),
            name: i.to_string(),
        })
    }

    /// Async lookup algorithm -- no work is done
    pub async fn lookup(self, query: Arc<Query>) -> Result<Vec<Lookup>> {
        let resolver = Arc::clone(&self.inner);

        let futures: Vec<_> = query.record_types
            .iter()
            .map(|x| make_lookup(&self.name, &resolver, x.clone()))
            .collect();

        let mut res = Vec::new();
        let stream = stream::iter(futures);
        let mut buffered_stream = stream.buffer_unordered(2);
        // TODO: https://rust-lang.github.io/async-book/05_streams/02_iteration_and_concurrency.html
        while let Some(f) = buffered_stream.next().await {
            trace!("Received lookup {:?}", f);
            let f = f?;
            res.push(f)
        }

        Ok(res)
    }
}

async fn make_lookup(i: &str, resolver: &TokioAsyncResolver, record_type: RecordType) -> Result<Lookup> {
    let lookup = resolver
        .lookup("www.example.com.", record_type, DnsRequestOptions::default())
        .await?;
    debug!("Received {} Lookup for record type {}.", i, record_type);

    Ok(lookup)
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

async fn do_main(query: Query) -> Result<Vec<Lookup>> {
    let query = Arc::new(query);

    let google = MyResolver::new(1).await?;
    let cloudflare = MyResolver::new(2).await?;
    let quad6 = MyResolver::new(3).await?;
    debug!("Created all the resolvers");

    let google_l = google.clone().lookup(Arc::clone(&query));
    let cloudflare_l = cloudflare.clone().lookup(Arc::clone(&query));
    let quad6_l = quad6.clone().lookup(Arc::clone(&query));
    debug!("Created all the futures");

    let tasks: Vec<task::JoinHandle<Result<Vec<Lookup>>>> = vec![google_l, cloudflare_l, quad6_l]
        .into_iter().map(task::spawn).collect();
    debug!("Spawned all the futures");

    let lookups = lookups(tasks).await;
    debug!("Awaited all the futures");

    lookups
}

#[derive(Debug)]
pub struct Query {
    name: String,
    record_types: Vec<RecordType>,
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

    let query = Query {
        name: "www.example.com".to_string(),
        record_types: vec![
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
    };

    let mut rt = tokio::runtime::Runtime::new()
        .expect("Failed to create runtime.");

    rt.block_on(async {
        let lookups = do_main(query).await;
        match lookups {
            //Ok(lookup) => info!("Lookup: {:#?}", lookup),
            Ok(_) => info!("Done."),
            Err(e) => error!("An error occurred: {}", e),
        }
    });

    Ok(())
}
