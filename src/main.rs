#![feature(never_type)]

mod proxy;
mod httptunnel;

use std::{ env, fs };
use std::net::SocketAddr;
use std::sync::{ Arc, Mutex };
use std::path::{ PathBuf, Path };
use std::collections::HashMap;
use failure::Fallible;
use serde::Deserialize;
use tokio::prelude::*;
use hyper::server::Server;
use trust_dns_resolver::AsyncResolver;
use structopt::StructOpt;
use directories::ProjectDirs;
use mitmca::{ Entry, CertStore };
use crate::proxy::Proxy;


#[derive(StructOpt)]
struct Options {
    #[structopt(short="c", long="config")]
    config: Option<PathBuf>
}

#[derive(Deserialize)]
struct Config {
    bind: SocketAddr,
    alpn: Option<String>,
    cert: PathBuf,
    mapping: HashMap<String, String>
}


fn main() -> Fallible<()> {
    let options = Options::from_args();

    let config_path = options.config
        .or_else(|| {
            ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
                .map(|dir| dir.config_dir().join("config.toml"))
        })
        .ok_or_else(|| failure::err_msg("missing config"))?;
    let config: Config = toml::from_slice(&fs::read(&config_path)?)?;

    let addr = config.bind;
    let cert_path = config_path
        .parent()
        .unwrap_or(&config_path)
        .join(&config.cert);
    let ca = Arc::new(Mutex::new(read_pkcs12(&cert_path)?));
    let (resolver, background) = AsyncResolver::from_system_conf()?;

    println!("mapping: {:#?}", config.mapping);

    let forward = Proxy {
        ca, resolver,
        alpn: config.alpn,
        mapping: config.mapping
    };

    let done = future::lazy(move || {
        hyper::rt::spawn(background);

        let srv = Server::bind(&addr)
            .serve(move || future::ok::<_, !>(forward.clone()));
        println!("bind: {:?}", srv.local_addr());
        srv.map_err(|err| eprintln!("proxy: {:?}", err))
    });

    hyper::rt::run(done);

    Ok(())
}


fn read_pkcs12(path: &Path) -> Fallible<CertStore> {
    use std::process::Command;
    use openssl::pkcs12::Pkcs12;

    fn askpass<F, T>(f: F)
        -> Fallible<T>
        where F: FnOnce(&str) -> Fallible<T>
    {
        const PROMPT: &str = "Password:";

        if let Ok(bin) = env::var("NOSNI_ASKPASS") {
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

    askpass(|pass| {
        let pkcs12 = Pkcs12::from_der(fs::read(path)?.as_ref())?
            .parse(pass)?;
        Ok(CertStore::from(Entry(pkcs12)))
    })
}
