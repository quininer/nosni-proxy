mod proxy;
mod httptunnel;

use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{ Arc, Mutex };
use std::path::{ PathBuf, Path };
use std::collections::HashMap;
use serde::Deserialize;
use tokio::runtime::{ self, Handle };
use hyper::rt::Executor;
use hyper::server::Server;
use hyper::service::{ make_service_fn, service_fn };
use trust_dns_resolver::AsyncResolver;
use anyhow::format_err;
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


fn main() -> anyhow::Result<()> {
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
        .ok_or_else(|| format_err!("missing config"))?;
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
    let (resolver, background) = AsyncResolver::from_system_conf()
        .map_err(|err| format_err!("failure: {:?}", err))?;

    let mut rt = runtime::Builder::new()
        .enable_all()
        .threaded_scheduler()
        .build()?;

    let forward = Proxy {
        ca, resolver,
        alpn: config.alpn,
        mapping: config.mapping,
        hosts: config.hosts.unwrap_or_default(),
        handle: rt.handle().clone()
    };

    let done = async move {
        forward.handle.spawn(background);

        let make_service = make_service_fn(|_| {
            let forward = forward.clone();
            async move {
                Ok::<_, !>(service_fn(move |req| proxy::call(forward.clone(), req)))
            }
        });

        let srv = Server::bind(&addr)
            .executor(HandleExecutor(forward.handle.clone()))
            .serve(make_service);
        println!("bind: {:?}", srv.local_addr());
        srv.await
    };

    rt.block_on(done)?;

    Ok(())
}

fn gen(name: &str) -> anyhow::Result<()> {
    use rustyline::Editor;
    use rand::{ Rng, rngs::OsRng };

    let mut rng = OsRng;

    let mut rl = Editor::<()>::new();
    let san = rl.readline("subject alt names> ")?
        .split(',')
        .map(str::to_string)
        .map(rcgen::SanType::DnsName)
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

fn read_root_cert(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertStore> {
    let cert_buf = fs::read_to_string(cert_path)?;
    let key_buf = fs::read_to_string(key_path)?;
    let entry = Entry::from_pem(&cert_buf, &key_buf)?;
    Ok(CertStore::from(entry))
}

#[derive(Clone)]
struct HandleExecutor(Handle);

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for HandleExecutor {
    fn execute(&self, fut: F) {
        self.0.spawn(fut);
    }
}
