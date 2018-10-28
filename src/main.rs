#![feature(never_type)]

mod proxy;
mod httptunnel;

use std::env;
use std::net::SocketAddr;
use std::sync::{ Arc, Mutex };
use failure::Fallible;
use tokio::prelude::*;
use hyper::client::HttpConnector;
use hyper::server::Server;
use native_tls::{ Identity, TlsConnector, TlsAcceptor };
use trust_dns_resolver::AsyncResolver;
use mitmca::{ Entry, CertStore };
use crate::proxy::Proxy;


fn main() -> Fallible<()> {
    let mut iter = env::args().skip(1);

    let addr = if let Some(addr) = iter.next() {
        addr.parse()?
    } else {
        SocketAddr::from(([127, 0, 0, 1], 1087))
    };

    let alpn = env::var("NOSNI_ALPN").ok();
    let ca = Arc::new(Mutex::new(read_pkcs12(iter.next())?));
    let (resolver, background) = AsyncResolver::from_system_conf()?;

    let forward = Proxy { alpn, ca, resolver };

    let done = future::lazy(move || {
        hyper::rt::spawn(background);

        let srv = Server::bind(&addr)
            .serve(move || future::ok::<_, !>(forward.clone()));
        println!("bind: {:?}", srv.local_addr());
        srv.map_err(|err| eprintln!("{:?}", err))
    });

    hyper::rt::run(done);

    Ok(())
}


fn read_pkcs12(path: Option<String>) -> Fallible<CertStore> {
    use std::fs;
    use std::process::Command;
    use openssl::pkcs12::Pkcs12;

    fn askpass<F, T>(f: F)
        -> Fallible<T>
        where F: FnOnce(&str) -> Fallible<T>
    {
        const PROMPT: &str = "Password:";

        if let Ok(bin) = env::var("ENE_ASKPASS") {
            Command::new(bin)
                .arg(PROMPT)
                .output()
                .map_err(Into::into)
                .and_then(|output| {
                    let pw = String::from_utf8(output.stdout)?;
                    f(&pw)
                })
        } else {
            ttyaskpass::askpass(PROMPT, f)
        }
    }

    let path = path.or_else(|| env::var("NOSNI_P12_PATH").ok())
        .ok_or_else(|| failure::err_msg("need pkcs12"))?;

    askpass(|pass| {
        let pkcs12 = Pkcs12::from_der(fs::read(path)?.as_ref())?
            .parse(pass)?;
        Ok(CertStore::from(Entry(pkcs12)))
    })
}
