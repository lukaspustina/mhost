// TODO: deny missing docs
#![allow(missing_docs)]

use futures::{Future, Stream};
use hyper::Client;
use tokio_core::reactor::Handle;
use serde_json;

// TODO: use https
static BASE_URI: &'static &str = &"http://www.ungefiltert-surfen.de/nameserver";

#[derive(Deserialize)]
pub struct Server {
    pub ip: String,
    pub name: String,
    pub country_id: String,
    pub city: Option<String>,
    pub version: Option<String>,
    pub error: Option<String>,
    pub dnssec: bool,
    pub reliability: f32,
    pub checked_at: String,
    pub created_at: String,
}

pub fn retrieve_servers(loop_handle: &Handle, country_id: &str) -> Box<Future<Item=Vec<Server>, Error=Error>> {
    let uri = format!("{}/{}.json", BASE_URI, country_id);
    let uri = uri.parse().unwrap();// TODO: .chain_err(|| ErrorKind::RetrievalError);
    let client = Client::new(loop_handle);

    Box::new(
        client.get(uri).and_then(|res| {
            res.body().concat2().and_then(move |body| {
                // TODO: Error
                let v: Vec<Server> = serde_json::from_slice(&body).unwrap();

                Ok(v)
            })
        }).map_err(move |e| {
            Error::with_chain(e, ErrorKind::RetrievalError)
        })
    )
}

error_chain! {
    errors {
        RetrievalError {
            description("Failed to retrieve DNS servers")
            display("Failed to retrieve DNS servers")
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio_core::reactor::Core;

    #[test]
    fn retrieve_de_servers() {
        let mut io_loop = Core::new().unwrap();

        let retrieve = retrieve_servers(&io_loop.handle(), "de");
        let result = io_loop.run(retrieve);
        let servers: Vec<Server> = result.unwrap();

        assert!(servers.len() > 0);
    }
}