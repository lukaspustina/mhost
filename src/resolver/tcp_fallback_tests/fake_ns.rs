//! Deterministic fake nameserver on loopback: UDP and TCP share one ephemeral port.
//!
//! UDP either answers with the full TXT set or with TC set and no answers; TCP always answers
//! with the full TXT set (2-byte length prefix) and counts accepted connections.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::rdata::TXT;
use hickory_resolver::proto::rr::{RData, Record};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

pub(crate) struct FakeNs {
    addr: SocketAddr,
    tcp_connections: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeNs {
    /// Starts the fake nameserver. `udp_truncates`: UDP answers TC with no answers; otherwise
    /// UDP answers with `txt_records` in full.
    pub(crate) async fn start(udp_truncates: bool, txt_records: Vec<String>) -> FakeNs {
        let (tcp, udp) = bind_pair().await;
        let addr = tcp.local_addr().expect("local addr");
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let txt_records = Arc::new(txt_records);

        let udp_task = tokio::spawn(serve_udp(udp, udp_truncates, txt_records.clone()));
        let tcp_task = tokio::spawn(serve_tcp(tcp, tcp_connections.clone(), txt_records));

        FakeNs {
            addr,
            tcp_connections,
            tasks: vec![udp_task, tcp_task],
        }
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn tcp_connections(&self) -> usize {
        self.tcp_connections.load(Ordering::SeqCst)
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

fn answer(request: &[u8], truncate: bool, txt_records: &[String]) -> Option<Vec<u8>> {
    let request = Message::from_vec(request).ok()?;
    let query = request.queries.first()?.clone();
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    if truncate {
        response.metadata.truncation = true;
    } else {
        for txt in txt_records {
            let rdata = RData::TXT(TXT::new(vec![txt.clone()]));
            response.add_answer(Record::from_rdata(query.name().clone(), 300, rdata));
        }
    }
    response.to_vec().ok()
}

async fn serve_udp(socket: UdpSocket, truncates: bool, txt_records: Arc<Vec<String>>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        if let Some(reply) = answer(&buf[..len], truncates, &txt_records) {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}

async fn serve_tcp(listener: TcpListener, connections: Arc<AtomicUsize>, txt_records: Arc<Vec<String>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        connections.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(serve_tcp_connection(stream, txt_records.clone()));
    }
}

async fn serve_tcp_connection(mut stream: TcpStream, txt_records: Arc<Vec<String>>) {
    loop {
        let mut len = [0u8; 2];
        if stream.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut request = vec![0u8; u16::from_be_bytes(len) as usize];
        if stream.read_exact(&mut request).await.is_err() {
            return;
        }
        let Some(reply) = answer(&request, false, &txt_records) else {
            return;
        };
        let prefix = (reply.len() as u16).to_be_bytes();
        if stream.write_all(&prefix).await.is_err() || stream.write_all(&reply).await.is_err() {
            return;
        }
    }
}
