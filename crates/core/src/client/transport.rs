//! TCP (+ TLS for `https`) connections with byte counting.
//!
//! The rustls config and root store are built per connection and dropped
//! with it, so nothing stays resident while the agent is idle (spike B).

use std::{
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use super::{ClientError, Counters, ServerUrl};

/// Counts bytes crossing the TCP socket.
pub(crate) struct Counting {
    inner: TcpStream,
    counters: Arc<Counters>,
}

impl AsyncRead for Counting {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len().saturating_sub(before);
        self.counters
            .bytes_in
            .fetch_add(n as u64, Ordering::Relaxed);
        r
    }
}

impl AsyncWrite for Counting {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            self.counters
                .bytes_out
                .fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A plain or TLS connection.
pub(crate) enum Stream {
    Plain(Counting),
    Tls(Box<TlsStream<Counting>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, data),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// The server's addresses from the last lookup, reused for up to
/// [`DNS_REUSE`]: each lookup brings up OS thread-pool workers in the idle
/// agent (resource-budget.md §2). TLS still checks the certificate against
/// the host name, so a stale address can only fail, never impersonate.
static RESOLVED: std::sync::Mutex<Option<Resolved>> = std::sync::Mutex::new(None);
const DNS_REUSE: std::time::Duration = std::time::Duration::from_secs(600);
/// Addresses tried per connect. A blocking connect to an address that drops
/// packets waits for the OS timeout (about 21 s on Windows), so a long list
/// could hold the blocking pool for minutes.
const MAX_ADDRS: usize = 2;

struct Resolved {
    host: String,
    port: u16,
    addrs: Vec<std::net::SocketAddr>,
    at: std::time::Instant,
}

fn cached_addrs(host: &str, port: u16) -> Option<Vec<std::net::SocketAddr>> {
    let g = RESOLVED.lock().ok()?;
    let r = g.as_ref()?;
    (r.host == host && r.port == port && r.at.elapsed() < DNS_REUSE).then(|| r.addrs.clone())
}

fn remember_addrs(host: &str, port: u16, addrs: Option<Vec<std::net::SocketAddr>>) {
    if let Ok(mut g) = RESOLVED.lock() {
        *g = addrs.map(|addrs| Resolved {
            host: host.to_owned(),
            port,
            addrs,
            at: std::time::Instant::now(),
        });
    }
}

/// TCP to `host:port`, from the cached addresses when they are fresh. Lookup
/// and connect run on tokio's blocking pool (the agent caps it at one thread
/// that ends a second after its last job), and the connect is a blocking one:
/// a non-blocking connect makes Winsock start its own helper thread
/// (`mswsock!SockAsyncThread`), which stays for five minutes and, when it
/// ends, brings up three thread-pool workers. That pushed the idle agent over
/// its thread budget (resource-budget.md §4, 2026-10-16).
async fn tcp_connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let host = host.to_owned();
    let s = tokio::task::spawn_blocking(move || blocking_connect(&host, port))
        .await
        .map_err(|_| io::Error::other("connect task"))??;
    s.set_nonblocking(true)?;
    TcpStream::from_std(s)
}

fn blocking_connect(host: &str, port: u16) -> io::Result<std::net::TcpStream> {
    if let Some(addrs) = cached_addrs(host, port) {
        if let Ok(s) = connect_first(&addrs) {
            return Ok(s);
        }
        remember_addrs(host, port, None);
    }
    let addrs: Vec<std::net::SocketAddr> =
        std::net::ToSocketAddrs::to_socket_addrs(&(host, port))?.collect();
    let s = connect_first(&addrs)?;
    remember_addrs(host, port, Some(addrs));
    Ok(s)
}

/// Tries the first [`MAX_ADDRS`] addresses in order.
fn connect_first(addrs: &[std::net::SocketAddr]) -> io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect(addrs.get(..MAX_ADDRS).unwrap_or(addrs))
}

/// Opens a connection to the server (no timeout here; callers wrap it).
pub(crate) async fn connect(
    url: &ServerUrl,
    counters: &Arc<Counters>,
) -> Result<Stream, ClientError> {
    let tcp = tcp_connect(&url.host, url.port)
        .await
        .map_err(|_| ClientError::Connect)?;
    tcp.set_nodelay(true).map_err(|_| ClientError::Connect)?;
    let counting = Counting {
        inner: tcp,
        counters: counters.clone(),
    };
    if !url.tls {
        return Ok(Stream::Plain(counting));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ClientError::Tls)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name =
        rustls::pki_types::ServerName::try_from(url.host.clone()).map_err(|_| ClientError::Tls)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, counting)
        .await
        .map_err(|_| ClientError::Tls)?;
    Ok(Stream::Tls(Box::new(tls)))
}
