#![feature(never_type)]

mod proxy;
mod httpfwd;
mod httptunnel;

use std::net::SocketAddr;
use failure::Fallible;
use tokio::prelude::*;
use hyper::client::HttpConnector;
use hyper::server::Server;
use native_tls::{ Identity, TlsConnector, TlsAcceptor };
use trust_dns_resolver::AsyncResolver;
use crate::proxy::Proxy;


fn main() -> Fallible<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 1087));

    // TODO use trust-dns
    // https://github.com/hyperium/hyper/issues/1517
    let mut http = HttpConnector::new(4);
    http.enforce_http(false);
    let mut tls_builder = TlsConnector::builder();
    tls_builder.use_sni(false);
    let tls = tls_builder.build()?;
    let identity = Identity::from_pkcs12(std::fs::read("./certificate.p12")?.as_ref(), "")?;
    let serv = TlsAcceptor::new(identity)?;
    let (resolver, background) = AsyncResolver::from_system_conf()?;

    let forward = Proxy { http, tls, serv, resolver };

    let done = future::lazy(move || {
        hyper::rt::spawn(background);

        Server::bind(&addr)
            .serve(move || future::ok::<_, !>(forward.clone()))
            .map_err(|err| eprintln!("{:?}", err))
    });

    hyper::rt::run(done);

    Ok(())
}
