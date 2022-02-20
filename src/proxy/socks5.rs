use std::io;
use std::time::Duration;
use std::convert::TryFrom;
use std::sync::{ Arc, Mutex };
use std::net::{ SocketAddr, IpAddr, Ipv4Addr };
use std::marker::Unpin;
use anyhow::{ format_err, Context };
use once_cell::sync::Lazy;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::{
    copy_bidirectional,
    BufStream,
    AsyncRead, AsyncWrite,
    AsyncReadExt, AsyncWriteExt
};
use tokio_rustls::{ rustls, TlsConnector, client::TlsStream };
use trust_dns_resolver::{ AsyncResolver, TokioConnection, TokioConnectionProvider };

use futures::future::{ self, TryFutureExt };
use futures::stream::{ self, StreamExt };
use tower_layer::Layer;
use tower_util::{ service_fn, ServiceExt };
use tower_happy_eyeballs::HappyEyeballsLayer;

use mitmca::CertStore;
use crate::config::Config;


static LOCAL_SESSION_CACHE: Lazy<Arc<rustls::server::ServerSessionMemoryCache>> =
    Lazy::new(|| rustls::server::ServerSessionMemoryCache::new(32));
static REMOTE_SESSION_CACHE: Lazy<Arc<rustls::client::ClientSessionMemoryCache>> =
    Lazy::new(|| rustls::client::ClientSessionMemoryCache::new(32));


pub struct Proxy {
    pub ca: Arc<Mutex<CertStore>>,
    pub resolver: AsyncResolver<TokioConnection, TokioConnectionProvider>,
    pub config: Config,
}

impl Proxy {
    pub async fn call(self: Arc<Self>, stream: TcpStream) -> anyhow::Result<()> {
        let mut stream = BufStream::with_capacity(1024, 1024, stream);

        // local handshake
        //
        // Get target addr
        let addr = handshake(&mut stream).await?;

        println!("{:?}", addr);

        let (start_handshake, remote, hostname) = match addr {
            Address::Addr(addr) => {
                // socks5 response
                response(&mut stream, 0, addr).await?;

                // local tls handshake
                let stream = stream.into_inner();
                let acceptor = rustls::server::Acceptor::new()?;
                let start_handshake = tokio_rustls::LazyConfigAcceptor::new(acceptor, stream).await?;

                // Get hostname
                let hostname = start_handshake.client_hello()
                    .server_name()
                    .map(String::from)
                    .context("No server name")?;

                // remote connect
                let ips = std::iter::once(addr.ip());
                let remote = remote_connect(&self, hostname.clone(), ips, addr.port()).await?;

                (start_handshake, remote, hostname)
            },
            Address::Domain(hostname, port) => {
                // dns query & remote connect
                let remote = async {
                    let lookup = {
                        let server_name = self.config.hosts
                            .as_ref()
                            .and_then(|map| map.get(&hostname))
                            .unwrap_or(&hostname);

                        self.resolver.lookup_ip(server_name.as_str())
                    };
                    let ips = timeout(Duration::from_secs(5), lookup).await
                        .map_err(anyhow::Error::from)
                        .and_then(|ret| ret.map_err(anyhow::Error::from))
                        .with_context(|| format!("dns lookup failure: {}", hostname))?;

                    remote_connect(&self, hostname.clone(), ips, port).await
                };

                // socks5 error response
                let remote = match remote.await {
                    Ok(remote) => remote,
                    Err(err) => {
                        let reply = err.chain()
                            .find(|err| {
                                let kind = err.downcast_ref::<io::Error>().map(|err| err.kind());
                                kind == Some(io::ErrorKind::ConnectionRefused)
                            })
                            .map(|_| 5)
                            .unwrap_or(1);

                        let fake_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
                        response(&mut stream, reply, fake_addr).await?;
                        return Err(err);
                    }
                };

                // socks5 response
                let addr = remote.get_ref().0.local_addr()?;
                response(&mut stream, 0, addr).await?;

                // tls handshake
                let stream = stream.into_inner();
                let acceptor = rustls::server::Acceptor::new()?;
                let start_handshake = tokio_rustls::LazyConfigAcceptor::new(acceptor, stream).await?;

                (start_handshake, remote, hostname)
            }
        };

        // start local tls handshake
        let tls_config = {
            let (_io, session) = remote.get_ref();
            let alpn = session.alpn_protocol()
                .map(|proto| vec![Vec::from(proto)])
                .unwrap_or_else(Vec::new);
            let mut tls_config = self.ca.lock()
                .map_err(|_| format_err!("bad lock"))?
                .get(&hostname)?;
            tls_config.session_storage = LOCAL_SESSION_CACHE.clone();
            tls_config.alpn_protocols = alpn;
            Arc::new(tls_config)
        };
        let mut local = start_handshake.into_stream(tls_config).await?;
        let mut remote = remote;

        copy_bidirectional(&mut local, &mut remote)
            .await
            .with_context(|| format!("bidirectional copy stream error: {}", hostname))?;

        Ok(())
    }
}

#[derive(Debug)]
enum Address {
    Addr(SocketAddr),
    Domain(String, u16)
}

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

async fn handshake<S>(stream: &mut S)
    -> anyhow::Result<Address>
where
    S: AsyncRead + AsyncWrite + Unpin
{
    // read version
    {
        let version = stream.read_u8().await?;
        if version != v5::VERSION {
            anyhow::bail!("unimplemented version: {}", version);
        }
    }

    // read auth method
    {
        let len = stream.read_u8().await?;
        let len: usize = len.into();
        let mut buf = [0; 256];
        stream.read_exact(&mut buf[..len]).await?;
        if !buf[..len].contains(&v5::METH_NO_AUTH) {
            anyhow::bail!("no supported auth method given");
        }
    }

    // write version and auth method
    stream.write_all(&[v5::VERSION, v5::METH_NO_AUTH]).await?;
    stream.flush().await?;

    // read version
    {
        let version = stream.read_u8().await?;
        if version != v5::VERSION {
            anyhow::bail!("didn't confirm with v5 version");
        }
    }

    // read cmd
    {
        let cmd = stream.read_u8().await?;
        if cmd != v5::CMD_CONNECT {
            anyhow::bail!("unsupported command");
        }
    }

    // read addr
    let addr = {
        let _ = stream.read_u8().await?; // reserved
        let atyp = stream.read_u8().await?;
        match atyp {
            v5::ATYP_IPV4 => {
                let mut buf = [0; 4];
                stream.read_exact(&mut buf).await?;
                let port = stream.read_u16().await?;
                Address::Addr(SocketAddr::from((buf, port)))
            },
            v5::ATYP_IPV6 => {
                let mut buf = [0; 16];
                stream.read_exact(&mut buf).await?;
                let port = stream.read_u16().await?;
                Address::Addr(SocketAddr::from((buf, port)))
            },
            v5::ATYP_DOMAIN => {
                let len = stream.read_u8().await?;
                let len: usize = len.into();
                let mut buf = vec![0; len];
                stream.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf)?;
                let port = stream.read_u16().await?;

                if let Ok(addr) = domain.parse::<IpAddr>() {
                    Address::Addr(SocketAddr::from((addr, port)))
                } else {
                    Address::Domain(domain, port)
                }
            },
            _ => anyhow::bail!("unknown ATYP received: {}", atyp)
        }
    };

    Ok(addr)
}

async fn response<S>(stream: &mut S, reply: u8, addr: SocketAddr)
    -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin
{
    let mut buf = [0; 4];

    buf[0] = v5::VERSION;   // version
    buf[1] = reply;         // reply field
    buf[2] = 0x0;           // reserved

    match addr {
        SocketAddr::V4(addr) => {
            buf[3] = v5::ATYP_IPV4;
            stream.write_all(&buf).await?;
            stream.write_all(&addr.ip().octets()).await?;
            stream.write_all(&addr.port().to_be_bytes()).await?;
        },
        SocketAddr::V6(addr) => {
            buf[3] = v5::ATYP_IPV6;
            stream.write_all(&buf).await?;
            stream.write_all(&addr.ip().octets()).await?;
            stream.write_all(&addr.port().to_be_bytes()).await?;
        }
    }

    stream.flush().await?;

    Ok(())
}

fn build_tls_connector(proxy: &Proxy, server_name: &str)
    -> anyhow::Result<(TlsConnector, rustls::ServerName)>
{
    let sniname = proxy.config.mapping.get(server_name)
        .cloned();
    let dnsname = sniname
        .as_deref()
        .unwrap_or(server_name);
    let dnsname = rustls::ServerName::try_from(dnsname)
        .map_err(|_| anyhow::format_err!("bad dnsname: {:?}", dnsname))?;
    let dnsname = dnsname.to_owned();

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
        |ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        },
    ));
    let mut tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    tls_config.alpn_protocols = proxy.config.alpn.iter()
        .map(|protocol| Vec::from(protocol.as_bytes()))
        .collect();
    tls_config.enable_sni = sniname.is_some();
    tls_config.session_storage = REMOTE_SESSION_CACHE.clone();

    Ok((TlsConnector::from(Arc::new(tls_config)), dnsname))
}

pub async fn remote_connect<I>(proxy: &Proxy, server_name: String, ips: I, port: u16)
    -> anyhow::Result<TlsStream<TcpStream>>
where
    I: IntoIterator<Item = IpAddr>
{
    let (tls_connector, dnsname) = build_tls_connector(proxy, &server_name)?;

    let make_conn = service_fn(|ip| {
        TcpStream::connect((ip, port))
            .and_then(|stream| {
                let ret = stream.set_nodelay(true)
                    .map(|_| stream);
                future::ready(ret)
            })
            .and_then(|stream| tls_connector.connect(dnsname.clone(), stream))
    });

    let remote = HappyEyeballsLayer::new()
        .layer(make_conn)
        .oneshot(stream::iter(ips).fuse()).await?;

    let (io, _session) = remote.get_ref();
    io.set_nodelay(false)?;
    Ok(remote)
}
