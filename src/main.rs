mod proxy;
mod httptunnel;

#[cfg(feature = "mimallocator")]
#[global_allocator]
static GLOBAL: mimallocator::Mimalloc = mimallocator::Mimalloc;

use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{ Arc, Mutex };
use std::path::{ PathBuf, Path };
use std::collections::HashMap;
use serde::Deserialize;
use tokio::runtime::{ self, Handle };
use tokio_rustls::rustls;
use hyper::rt::Executor;
use hyper::server::Server;
use hyper::service::{ make_service_fn, service_fn };
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::{ ResolverConfig, ResolverOpts, NameServerConfigGroup };
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
    doh: Option<Doh>,
    mapping: HashMap<String, String>,
    hosts: Option<HashMap<String, String>>
}

#[derive(Deserialize)]
struct Doh {
    addr: SocketAddr,
    name: String,

    #[serde(default)]
    sni: bool,

    #[cfg_attr(not(feature = "dnssec"), allow(dead_code))]
    #[serde(default)]
    dnssec: bool
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

    let mut rt = runtime::Builder::new()
        .enable_all()
        .threaded_scheduler()
        .build()?;
    let handle = rt.handle().clone();

    let done = async move {
        let resolver = if let Some(doh) = config.doh {
            let mut tls_config = rustls::ClientConfig::new();
            tls_config.enable_sni = doh.sni;
            tls_config.enable_early_data = true;
            tls_config.set_protocols(&[b"h2".to_vec()]);
            tls_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            let tls_config = Arc::new(tls_config);

            let server = NameServerConfigGroup::from_ips_https(
                &[doh.addr.ip()], doh.addr.port(),
                doh.name, false
            );
            let mut config = ResolverConfig::from_parts(None, Vec::new(), server);
            config.set_tls_client_config(tls_config);

            #[allow(unused_mut)]
            let mut opts = ResolverOpts::default();

            #[cfg(feature = "dnssec")] {
                opts.validate = doh.dnssec;
            }

            AsyncResolver::new(config, opts, handle.clone())?
        } else {
            AsyncResolver::from_system_conf(handle.clone())?
        };

        let forward = Arc::new(Proxy {
            ca, resolver,
            alpn: config.alpn,
            mapping: config.mapping,
            hosts: config.hosts.unwrap_or_default(),
            handle: handle.clone()
        });

        let make_service = make_service_fn(|_| {
            let forward = forward.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| proxy::call(forward.clone(), req)))
            }
        });

        let srv = Server::bind(&addr)
            .executor(HandleExecutor(handle))
            .serve(make_service);
        println!("bind: {:?}", srv.local_addr());
        srv.await.map_err(anyhow::Error::from)
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
