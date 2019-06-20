use std::sync::Arc;
use std::net::SocketAddr;
use lazy_static::lazy_static;
use failure::{ Fallible, err_msg };
use tokio::prelude::*;
use tokio::io as aio;
use tokio::net::TcpStream;
use tokio_rustls::{ rustls, webpki, TlsAcceptor, TlsConnector };
use tokio_rustls::rustls::Session;
use hyper::{ Request, Response, Body };
use hyper::service::Service;
use percent_encoding::percent_decode;
use crate::proxy::Proxy;


macro_rules! and {
    ( $fut:expr, $( $t:expr ),+ ) => {
        $fut.map(move |x| (x, $( $t ),+))
    }
}


lazy_static!{
    static ref LOCAL_SESSION_CACHE: Arc<rustls::ServerSessionMemoryCache> = rustls::ServerSessionMemoryCache::new(32);
    static ref REMOTE_SESSION_CACHE: Arc<rustls::ClientSessionMemoryCache> = rustls::ClientSessionMemoryCache::new(32);
}

pub fn call(proxy: &mut Proxy, req: Request<<Proxy as Service>::ReqBody>)
    -> Fallible<<Proxy as Service>::Future>
{
    let Proxy { alpn, ca, resolver, .. } = proxy;
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
        .ok_or_else(|| err_msg("missing host"))?;
    let target = proxy.hosts.get(&hostname)
        .cloned()
        .unwrap_or_else(|| hostname.clone());
    let sniname = proxy.mapping.get(&hostname)
        .cloned();
    let dnsname = sniname
        .as_ref()
        .unwrap_or(&hostname);
    let dnsname = webpki::DNSNameRef::try_from_ascii_str(dnsname)
        .map_err(|_| err_msg("bad dnsname"))?;
    let dnsname = dnsname.to_owned();

    tls_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    tls_config.enable_sni = sniname.is_some();
    tls_config.set_persistence(REMOTE_SESSION_CACHE.clone());
    let connector = TlsConnector::from(Arc::new(tls_config));

    let fut = req.into_body()
        .on_upgrade()
        .map_err(failure::Error::from)
        .and_then(move |upgraded| {
            let fut = resolver.lookup_ip(target.as_str())
                .map_err(Into::into)
                .and_then(|lookup| lookup.iter()
                    .next()
                    .ok_or_else(|| err_msg("ip not found")))
                .and_then(move |ip| {
                    println!(">>> {:?}", ip);
                    let addr = SocketAddr::from((ip, port));
                    TcpStream::connect(&addr)
                        .map_err(Into::into)
                        .and_then(move |remote| {
                            let fut = connector.connect(dnsname.as_ref(), remote)
                                .map_err(Into::into);
                            and!(fut, hostname)
                        })
                });
            and!(fut, upgraded)
        })
        .and_then(move |((remote, name), upgraded)| {
            let (_, session) = remote.get_ref();
            let alpn = session.get_alpn_protocol()
                .map(|proto| vec![Vec::from(proto)])
                .unwrap_or_else(Vec::new);

            let mut tls_config = ca.lock()
                .map_err(|_| err_msg("deadlock"))?
                .get(&name)?;
            tls_config.set_persistence(LOCAL_SESSION_CACHE.clone());
            tls_config.set_protocols(&alpn);

            let acceptor = TlsAcceptor::from(Arc::new(tls_config));
            Ok((acceptor, remote, upgraded))
        })
        .and_then(|(acceptor, remote, upgraded)| {
            let fut = acceptor.accept(upgraded)
                .map_err(Into::into);
            and!(fut, remote)
        })
        .and_then(|(local, remote)| {
            let (remote_read, remote_write) = remote.split();
            let (local_read, local_write) = local.split();

            aio::copy(remote_read, local_write)
                .map(drop)
                .select2(aio::copy(local_read, remote_write).map(drop))
                .map(drop)
                .map_err(|res| res.split().0.into())
        })
        .map_err(|err| eprintln!("connect: {:?}", err));

    hyper::rt::spawn(fut);

    Ok(Box::new(future::ok(Response::new(Body::empty()))))
}
