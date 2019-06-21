#![feature(never_type)]

mod proxy;
mod httptunnel;

use std::fs;
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
    config: Option<PathBuf>,

    /// generate cert and key
    #[structopt(long="gen")]
    gen: Option<String>
}

#[derive(Deserialize)]
struct Config {
    bind: SocketAddr,
    alpn: Option<String>,
    cert: PathBuf,
    key: PathBuf,
    mapping: HashMap<String, String>,
    hosts: Option<HashMap<String, String>>
}


fn main() -> Fallible<()> {
    let options = Options::from_args();

    if let Some(name) = options.gen {
        gen(&name)?;
        return Ok(());
    }


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
    let key_path = config_path
        .parent()
        .unwrap_or(&config_path)
        .join(&config.key);
    let ca = Arc::new(Mutex::new(read_root_cert(&cert_path, &key_path)?));
    let (resolver, background) = AsyncResolver::from_system_conf()?;

    let forward = Proxy {
        ca, resolver,
        alpn: config.alpn,
        mapping: config.mapping,
        hosts: config.hosts.unwrap_or_default()
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

fn gen(name: &str) -> Fallible<()> {
    use rustyline::Editor;
    use rand::{ Rng, rngs::OsRng };

    let mut rng = OsRng::new()?;

    let mut rl = Editor::<()>::new();
    let san = rl.readline("subject alt names> ")?
        .split(',')
        .map(str::to_string)
        .collect::<Vec<_>>();
    let on = rl.readline("organization name> ")?;
    let cn = rl.readline("common name> ")?;

    let mut params = rcgen::CertificateParams::default();
    params.serial_number = Some(rng.gen());
    params.subject_alt_names = san;
    params.distinguished_name.push(rcgen::DnType::OrganizationName, on);
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = rcgen::Certificate::from_params(params)?;

    let cert = ca_cert.serialize_pem()?;
    let key = ca_cert.serialize_private_key_pem();

    fs::write(format!("{}-ca-cert.pem", name), cert.as_bytes())?;
    fs::write(format!("{}-ca.pem", name), key.as_bytes())?;

    Ok(())
}

fn read_root_cert(cert_path: &Path, key_path: &Path) -> Fallible<CertStore> {
    let cert_buf = fs::read_to_string(cert_path)?;
    let key_buf = fs::read_to_string(key_path)?;
    let entry = Entry::from_pem(&cert_buf, &key_buf)?;
    Ok(CertStore::from(entry))
}
