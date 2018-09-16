#![feature(never_type)]

mod proxy;
mod httpfwd;

use std::io;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::prelude::*;
use hyper::client::HttpConnector;
use hyper::server::Server;
use native_tls::TlsConnector;
use hyper_tls::HttpsConnector;
use crate::proxy::Proxy;


fn main() -> io::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 1087));

    let mut http = HttpConnector::new(4);
    http.enforce_http(false);
    let mut tls_builder = TlsConnector::builder();
    tls_builder.use_sni(false);
    let tls = tls_builder.build()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let https = HttpsConnector::from((http, tls));
    let forward = Proxy { tls: Arc::new(https) };

    let done = Server::bind(&addr)
        .serve(move || future::ok::<_, !>(forward.clone()))
        .map_err(|err| eprintln!("{:?}", err));

    hyper::rt::run(done);

    Ok(())
}
