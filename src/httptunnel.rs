use std::io;
use std::sync::Arc;
use std::net::SocketAddr;
use lazy_static::lazy_static;
use anyhow::format_err;
use futures::future::{ self, TryFutureExt };
use tokio::io::{ split, copy };
use tokio::net::TcpStream;
use tokio_rustls::{ rustls, webpki, TlsAcceptor, TlsConnector };
use tokio_rustls::rustls::Session;
use hyper::{ Request, Body };
use percent_encoding::percent_decode;
use crate::proxy::Proxy;

use futures::stream::{ self, StreamExt };
use tower_layer::Layer;
use tower_util::{ service_fn, ServiceExt };
use tower_limit::ConcurrencyLimit;
use tower_happy_eyeballs::HappyEyeballsLayer;



lazy_static!{
    static ref LOCAL_SESSION_CACHE: Arc<rustls::ServerSessionMemoryCache> =
        rustls::ServerSessionMemoryCache::new(32);
    static ref REMOTE_SESSION_CACHE: Arc<rustls::ClientSessionMemoryCache> =
        rustls::ClientSessionMemoryCache::new(32);
}

pub fn call(proxy: &Proxy, req: Request<Body>) -> anyhow::Result<()> {
    let Proxy { alpn, ca, resolver, handle, .. } = proxy;
    let ca = ca.clone();
    let resolver = resolver.clone();
    let port = req.uri().port_u16().unwrap_or(443);
    let maybe_alpn = req.headers()
        .get("ALPN")
        .and_then(|val| val.to_str().ok())
        .or_else(|| alpn.as_ref().map(String::as_str));

    let mut tls_config = rustls::ClientConfig::new();
    if let Some(val) = maybe_alpn {
        let alpn = val.split(',')
            .filter_map(|protocol| percent_decode(protocol.trim().as_bytes())
                .decode_utf8()
                .ok())
            .fold(Vec::new(), |mut sum, next| {
                sum.push(next.into_owned().into_bytes());
                sum
            });
        tls_config.set_protocols(&alpn);
    }

    let hostname = req.uri()
        .host()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format_err!("missing host"))?;
    let target = proxy.hosts.get(&hostname)
        .cloned()
        .unwrap_or_else(|| hostname.clone());
    let sniname = proxy.mapping.get(&hostname)
        .cloned();
    let dnsname = sniname
        .as_ref()
        .unwrap_or(&hostname);
    let dnsname = webpki::DNSNameRef::try_from_ascii_str(dnsname)
        .map_err(|_| format_err!("bad dnsname"))?;
    let dnsname = dnsname.to_owned();

    tls_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    tls_config.enable_sni = sniname.is_some();
    tls_config.set_persistence(REMOTE_SESSION_CACHE.clone());
    let connector = TlsConnector::from(Arc::new(tls_config));

    let make_conn =
        service_fn(move |ip| TcpStream::connect(SocketAddr::from((ip, port))));
    let make_conn = ConcurrencyLimit::new(make_conn, 5);

    let fut = async move {
        let upgraded = req
            .into_body()
            .on_upgrade()
            .await?;

        let ips = resolver.lookup_ip(target.as_str())
            .await
            .map_err(|err| format_err!("failure: {:?}", err))?;

        let remote = HappyEyeballsLayer::new(dns_not_found)
            .layer(make_conn)
            .oneshot(stream::iter(ips).fuse()).await?;

        println!(">>> {:?}", remote.peer_addr());

        remote.set_nodelay(true)?;
        let remote = connector.connect(dnsname.as_ref(), remote).await?;

        let (io, session) = remote.get_ref();
        io.set_nodelay(false)?;
        let alpn = session.get_alpn_protocol()
            .map(|proto| vec![Vec::from(proto)])
            .unwrap_or_else(Vec::new);

        let acceptor = {
            let mut tls_config = ca.lock()
                .map_err(|_| format_err!("deadlock"))?
                .get(&hostname)?;
            tls_config.set_persistence(LOCAL_SESSION_CACHE.clone());
            tls_config.set_protocols(&alpn);
            TlsAcceptor::from(Arc::new(tls_config))
        };

        let local = acceptor.accept(upgraded).await?;

        let (mut rr, mut rw) = split(remote);
        let (mut lr, mut lw) = split(local);

        future::select(copy(&mut lr, &mut rw), copy(&mut rr, &mut lw))
            .await
            .factor_first()
            .0?;

        Ok(()) as anyhow::Result<()>
    }.map_err(|err| eprintln!("connect: {:?}", err));

    handle.spawn(fut);

    Ok(())
}

fn dns_not_found() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "dns lookup is empty!")
}
