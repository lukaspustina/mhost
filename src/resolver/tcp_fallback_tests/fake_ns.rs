//! Deterministic fake nameserver on loopback: UDP and TCP share one ephemeral port.
//!
//! UDP behaviour is configurable per query name (answer, truncate, drop); TCP either answers
//! (2-byte length prefix), accepts without ever answering, or has no listener at all. Every
//! query is logged per transport as (name, type), and accepted TCP connections are counted.
//! A queries are answered with 192.0.2.1, TXT queries with the configured records.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::rdata::{A, TXT};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpBehavior {
    Answer,
    Truncate,
    Drop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcpMode {
    Answer,
    /// Accepts connections and reads queries, but never replies.
    Silent,
    /// Nothing listens on TCP at the nameserver's port.
    NoListener,
}

/// A logged query: lowercase FQDN as sent (e.g. `example.com.`) and the record type (e.g. `TXT`).
pub(crate) type LoggedQuery = (String, String);

type QueryLog = Arc<Mutex<Vec<LoggedQuery>>>;

struct Behavior {
    default_udp: UdpBehavior,
    udp_by_name: HashMap<String, UdpBehavior>,
    txt_records: Vec<String>,
}

pub(crate) struct FakeNsBuilder {
    behavior: Behavior,
    tcp_mode: TcpMode,
}

impl FakeNsBuilder {
    pub(crate) fn new() -> Self {
        FakeNsBuilder {
            behavior: Behavior {
                default_udp: UdpBehavior::Answer,
                udp_by_name: HashMap::new(),
                txt_records: Vec::new(),
            },
            tcp_mode: TcpMode::Answer,
        }
    }

    /// UDP behaviour for names without their own rule (default: answer).
    pub(crate) fn udp_default(mut self, behavior: UdpBehavior) -> Self {
        self.behavior.default_udp = behavior;
        self
    }

    /// UDP behaviour for one query name, e.g. `drop.example.com.`, whatever the record type.
    pub(crate) fn udp_for(mut self, name: &str, behavior: UdpBehavior) -> Self {
        self.behavior.udp_by_name.insert(name.to_ascii_lowercase(), behavior);
        self
    }

    pub(crate) fn txt_records(mut self, records: Vec<String>) -> Self {
        self.behavior.txt_records = records;
        self
    }

    pub(crate) fn tcp(mut self, mode: TcpMode) -> Self {
        self.tcp_mode = mode;
        self
    }

    pub(crate) async fn start(self) -> FakeNs {
        let (tcp, udp) = bind_pair().await;
        let addr = tcp.local_addr().expect("local addr");
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let udp_log: QueryLog = Arc::new(Mutex::new(Vec::new()));
        let tcp_log: QueryLog = Arc::new(Mutex::new(Vec::new()));
        let behavior = Arc::new(self.behavior);

        let mut tasks = vec![tokio::spawn(serve_udp(udp, behavior.clone(), udp_log.clone()))];
        match self.tcp_mode {
            TcpMode::NoListener => drop(tcp),
            mode => tasks.push(tokio::spawn(serve_tcp(
                tcp,
                mode,
                tcp_connections.clone(),
                behavior,
                tcp_log.clone(),
            ))),
        }

        FakeNs {
            addr,
            tcp_connections,
            udp_log,
            tcp_log,
            tasks,
        }
    }
}

pub(crate) struct FakeNs {
    addr: SocketAddr,
    tcp_connections: Arc<AtomicUsize>,
    udp_log: QueryLog,
    tcp_log: QueryLog,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeNs {
    /// Starts the fake nameserver. `udp_truncates`: UDP answers TC with no answers; otherwise
    /// UDP answers with `txt_records` in full. TCP always answers.
    pub(crate) async fn start(udp_truncates: bool, txt_records: Vec<String>) -> FakeNs {
        let udp = if udp_truncates {
            UdpBehavior::Truncate
        } else {
            UdpBehavior::Answer
        };
        FakeNsBuilder::new()
            .udp_default(udp)
            .txt_records(txt_records)
            .start()
            .await
    }

    pub(crate) fn builder() -> FakeNsBuilder {
        FakeNsBuilder::new()
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn tcp_connections(&self) -> usize {
        self.tcp_connections.load(Ordering::SeqCst)
    }

    /// Queries that arrived over UDP, in arrival order (including dropped ones).
    pub(crate) fn udp_queries(&self) -> Vec<LoggedQuery> {
        self.udp_log.lock().expect("udp log").clone()
    }

    /// Queries that arrived over TCP, in arrival order.
    pub(crate) fn tcp_queries(&self) -> Vec<LoggedQuery> {
        self.tcp_log.lock().expect("tcp log").clone()
    }
}

impl Drop for FakeNs {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn bind_pair() -> (TcpListener, UdpSocket) {
    for _ in 0..100 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let port = tcp.local_addr().expect("tcp addr").port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await {
            return (tcp, udp);
        }
    }
    panic!("no ephemeral port free for both UDP and TCP on 127.0.0.1");
}

fn parse(request: &[u8]) -> Option<(Message, LoggedQuery)> {
    let request = Message::from_vec(request).ok()?;
    let query = request.queries.first()?;
    let logged = (
        query.name().to_ascii().to_ascii_lowercase(),
        query.query_type().to_string(),
    );
    Some((request, logged))
}

fn answer(request: &Message, truncate: bool, txt_records: &[String]) -> Option<Vec<u8>> {
    let query = request.queries.first()?.clone();
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    if truncate {
        response.metadata.truncation = true;
    } else {
        match query.query_type() {
            RecordType::TXT => {
                for txt in txt_records {
                    let rdata = RData::TXT(TXT::new(vec![txt.clone()]));
                    response.add_answer(Record::from_rdata(query.name().clone(), 300, rdata));
                }
            }
            RecordType::A => {
                let rdata = RData::A(A(Ipv4Addr::new(192, 0, 2, 1)));
                response.add_answer(Record::from_rdata(query.name().clone(), 300, rdata));
            }
            _ => {}
        }
    }
    response.to_vec().ok()
}

async fn serve_udp(socket: UdpSocket, behavior: Arc<Behavior>, log: QueryLog) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Some((request, logged)) = parse(&buf[..len]) else {
            continue;
        };
        let rule = behavior
            .udp_by_name
            .get(&logged.0)
            .copied()
            .unwrap_or(behavior.default_udp);
        log.lock().expect("udp log").push(logged);
        if rule == UdpBehavior::Drop {
            continue;
        }
        if let Some(reply) = answer(&request, rule == UdpBehavior::Truncate, &behavior.txt_records) {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}

async fn serve_tcp(
    listener: TcpListener,
    mode: TcpMode,
    connections: Arc<AtomicUsize>,
    behavior: Arc<Behavior>,
    log: QueryLog,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        connections.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(serve_tcp_connection(stream, mode, behavior.clone(), log.clone()));
    }
}

async fn serve_tcp_connection(mut stream: TcpStream, mode: TcpMode, behavior: Arc<Behavior>, log: QueryLog) {
    loop {
        let mut len = [0u8; 2];
        if stream.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut request = vec![0u8; u16::from_be_bytes(len) as usize];
        if stream.read_exact(&mut request).await.is_err() {
            return;
        }
        let Some((request, logged)) = parse(&request) else {
            return;
        };
        log.lock().expect("tcp log").push(logged);
        if mode == TcpMode::Silent {
            continue;
        }
        let Some(reply) = answer(&request, false, &behavior.txt_records) else {
            return;
        };
        let prefix = (reply.len() as u16).to_be_bytes();
        if stream.write_all(&prefix).await.is_err() || stream.write_all(&reply).await.is_err() {
            return;
        }
    }
}
