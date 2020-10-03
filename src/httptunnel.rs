use std::sync::Arc;
use lazy_static::lazy_static;
use anyhow::{ Context, format_err };
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
        .with_context(|| "missing host")?;
    let target = proxy.hosts.get(&hostname)
        .cloned()
        .unwrap_or_else(|| hostname.clone());
    let sniname = proxy.mapping.get(&hostname)
        .cloned();
    let dnsname = sniname
        .as_ref()
        .unwrap_or(&hostname);
    let dnsname = webpki::DNSNameRef::try_from_ascii_str(dnsname)
        .with_context(|| "bad dnsname")?;
    let dnsname = dnsname.to_owned();

    tls_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    tls_config.enable_sni = sniname.is_some();
    tls_config.set_persistence(REMOTE_SESSION_CACHE.clone());
    let connector = TlsConnector::from(Arc::new(tls_config));

    let fut = async move {
        let upgraded = req
            .into_body()
            .on_upgrade().await
            .with_context(|| "local upgraded")?;

        let ips = resolver.lookup_ip(target.as_str()).await
            .with_context(|| format!("dns lookup failure: {}", target))?;

        let make_conn = service_fn(|ip| {
            TcpStream::connect((ip, port))
                .and_then(|stream| {
                    let ret = stream.set_nodelay(true)
                        .map(|_| stream);
                    future::ready(ret)
                })
                .and_then(|stream| connector.connect(dnsname.as_ref(), stream))
        });

        let remote = HappyEyeballsLayer::new()
            .layer(make_conn)
            .oneshot(stream::iter(ips).fuse()).await
            .with_context(|| format!("remote connect: {}", hostname))?;

        let (io, session) = remote.get_ref();

        println!(">>> {:?} => {:?}", dnsname, io.peer_addr());

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

        let local = acceptor
            .accept(upgraded).await
            .with_context(|| format!("local tls connect: {}", hostname))?;

        let (mut rr, mut rw) = split(remote);
        let (mut lr, mut lw) = split(local);

        tokio::select!{
            ret = copy(&mut lr, &mut rw) =>
                ret.with_context(|| format!("local to remote transfer: {}", hostname))?,
            ret = copy(&mut rr, &mut lw) =>
                ret.with_context(|| format!("remote to local transfer: {}", hostname))?
        };

        Ok(()) as anyhow::Result<()>
    }.map_err(|err| eprintln!("connect: {:?}", err));

    handle.spawn(fut);

    Ok(())
}
