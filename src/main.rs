#![feature(never_type)]

mod httpfwd;

use std::io;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::prelude::*;
use hyper::client::HttpConnector;
use hyper::server::Server;
use rustls::ClientConfig;
use hyper_rustls::HttpsConnector;
use crate::httpfwd::Forward;


fn main() -> io::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 1087));

    let mut http = HttpConnector::new(4);
    http.enforce_http(false);
    let mut tls = ClientConfig::new();
    tls.enable_sni = false;
    tls.root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let https = HttpsConnector::from((http, tls));
    let forward = Forward { tls: Arc::new(https) };

    let done = Server::bind(&addr)
        .serve(move || future::ok::<_, !>(forward.clone()))
        .map_err(|err| eprintln!("{:?}", err));

    hyper::rt::run(done);

    Ok(())
}
