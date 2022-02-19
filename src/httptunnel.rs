use std::sync::Arc;
use std::time::Duration;
use std::convert::TryFrom;
use lazy_static::lazy_static;
use anyhow::{ Context, format_err };
use futures::future::{ self, TryFutureExt };
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{ rustls, TlsAcceptor, TlsConnector };
use hyper::{ Request, Body };
use percent_encoding::percent_decode;
use crate::proxy::Proxy;

use futures::stream::{ self, StreamExt };
use tower_layer::Layer;
use tower_util::{ service_fn, ServiceExt };
use tower_happy_eyeballs::HappyEyeballsLayer;



lazy_static!{
    static ref LOCAL_SESSION_CACHE: Arc<rustls::server::ServerSessionMemoryCache> =
        rustls::server::ServerSessionMemoryCache::new(32);
    static ref REMOTE_SESSION_CACHE: Arc<rustls::client::ClientSessionMemoryCache> =
        rustls::client::ClientSessionMemoryCache::new(32);
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

    let alpn = if let Some(val) = maybe_alpn {
        let alpn = val.split(',')
            .filter_map(|protocol| percent_decode(protocol.trim().as_bytes())
                .decode_utf8()
                .ok())
            .fold(Vec::new(), |mut sum, next| {
                sum.push(next.into_owned().into_bytes());
                sum
            });
        alpn
    } else {
        Vec::new()
    };

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
    let dnsname = rustls::ServerName::try_from(dnsname.as_str())
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
    tls_config.alpn_protocols = alpn;
    tls_config.enable_sni = sniname.is_some();
    tls_config.session_storage = REMOTE_SESSION_CACHE.clone();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let fut = async move {
        let upgraded = hyper::upgrade::on(req).await
            .with_context(|| "local upgraded")?;

        let ips = timeout(Duration::from_secs(5), resolver.lookup_ip(target.as_str())).await
            .map_err(anyhow::Error::from)
            .and_then(|ret| ret.map_err(anyhow::Error::from))
            .with_context(|| format!("dns lookup failure: {}", target))?;

        let make_conn = service_fn(|ip| {
            TcpStream::connect((ip, port))
                .and_then(|stream| {
                    let ret = stream.set_nodelay(true)
                        .map(|_| stream);
                    future::ready(ret)
                })
                .and_then(|stream| connector.connect(dnsname.clone(), stream))
        });

        let mut remote = HappyEyeballsLayer::new()
            .layer(make_conn)
            .oneshot(stream::iter(ips).fuse()).await
            .with_context(|| format!("remote connect: {}", hostname))?;

        let (io, session) = remote.get_ref();

        println!(">>> {:?} => {:?}", dnsname, io.peer_addr());

        io.set_nodelay(false)?;

        let alpn = session.alpn_protocol()
            .map(|proto| vec![Vec::from(proto)])
            .unwrap_or_else(Vec::new);

        let acceptor = {
            let mut tls_config = ca.lock()
                .map_err(|_| format_err!("deadlock"))?
                .get(&hostname)?;
            tls_config.session_storage = LOCAL_SESSION_CACHE.clone();
            tls_config.alpn_protocols = alpn;
            TlsAcceptor::from(Arc::new(tls_config))
        };

        let mut local = acceptor
            .accept(upgraded).await
            .with_context(|| format!("local tls connect: {}", hostname))?;

        copy_bidirectional(&mut local, &mut remote)
            .await
            .with_context(|| format!("bidirectional copy stream error: {}", hostname))?;

        Ok(()) as anyhow::Result<()>
    }.map_err(|err| eprintln!("connect: {:?}", err));

    handle.spawn(fut);

    Ok(())
}
