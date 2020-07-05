use futures::stream::{self, StreamExt};
use log::{self, *};
use std::future::Future;
use std::io::Write;
use std::sync::Arc;
use tokio::task;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
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

#[derive(Debug)]
pub enum MyLookup {
    Lookup(Lookup),
    NxDomain,
    Timeout,
    Error,
}

impl From<std::result::Result<Lookup, ResolveError>> for MyLookup {
    fn from(res: std::result::Result<Lookup, ResolveError>) -> Self {
        match res {
            Ok(lookup) => MyLookup::Lookup(lookup),
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => MyLookup::NxDomain,
                ResolveErrorKind::Timeout => MyLookup::Timeout,
                _ => MyLookup::Error,
            },
        }
    }
}

impl MyResolver {
    pub async fn new(i: usize) -> Result<Self> {
        let config = match i {
            1 => ResolverConfig::google(),
            2 => ResolverConfig::cloudflare(),
            _ => ResolverConfig::quad9(),
        };
        let opts = ResolverOpts {
            //validate: true,
            ..ResolverOpts::default()
        };
        let resolver = TokioAsyncResolver::tokio(config, opts).await?;
        debug!("Created {} Resolver.", i);

        Ok(MyResolver {
            inner: Arc::new(resolver),
            name: i.to_string(),
        })
    }

    /// Async lookup algorithm -- no work is done
    pub fn lookup(&self, query: Arc<Query>) -> impl Future<Output = Vec<MyLookup>> {
        Self::inner_lookup(self.clone(), query)
    }

    async fn inner_lookup(resolver: Self, query: Arc<Query>) -> Vec<MyLookup> {
        let futures: Vec<_> = query
            .record_types
            .iter()
            .map(|x| make_lookup(&resolver.name, &resolver.inner, x.clone()))
            .collect();

        stream::iter(futures)
            .buffer_unordered(2)
            .inspect(|lookup| trace!("Received lookup {:?}", lookup))
            .collect::<Vec<MyLookup>>()
            .await
    }
}

async fn make_lookup(i: &str, resolver: &TokioAsyncResolver, record_type: RecordType) -> MyLookup {
    let lookup = resolver
        .lookup("www.example.com.", record_type, DnsRequestOptions::default())
        .await
        .into();
    debug!("Received {} Lookup for record type {}.", i, record_type);

    lookup
}

/// Wait asyncly for the work to finish
async fn lookups(tasks: Vec<task::JoinHandle<Vec<MyLookup>>>) -> Vec<MyLookup> {
    let mut res = Vec::new();
    for t in tasks {
        let r = t.await;
        res.push(r);
    }

    res.into_iter().flatten().flatten().collect()
}

async fn do_main(query: Query) -> Result<Vec<MyLookup>> {
    let query = Arc::new(query);

    let google = MyResolver::new(1).await?;
    let cloudflare = MyResolver::new(2).await?;
    let quad6 = MyResolver::new(3).await?;
    debug!("Created all the resolvers");

    let tasks: Vec<task::JoinHandle<Vec<MyLookup>>> = vec![google, cloudflare, quad6]
        .iter()
        .map(|resolver| resolver.lookup(query.clone()))
        .map(task::spawn)
        .collect();
    debug!("Created and spawned all the futures");

    let lookups = lookups(tasks).await;
    debug!("Awaited all the futures");

    Ok(lookups)
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
            let thread_id = &thread_id_string[9..thread_id_string.len() - 1];
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
            RecordType::MX,
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::TXT,
            RecordType::TXT,
        ],
    };

    let mut rt = tokio::runtime::Runtime::new().expect("Failed to create runtime.");

    rt.block_on(async {
        let lookups = do_main(query).await;
        match lookups {
            //Ok(lookups) => info!("Lookup: {:#?}", lookups),
            Ok(_) => info!("Done."),
            Err(e) => error!("An error occurred: {}", e),
        }
    });

    Ok(())
}
