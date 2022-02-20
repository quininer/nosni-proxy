mod httptunnel;

use std::fs;
use std::time::Duration;
use std::sync::{ Arc, Mutex };
use std::path::{ PathBuf, Path };
use tokio_rustls::rustls;
use hyper::server::Server;
use hyper::service::{ make_service_fn, service_fn };
use trust_dns_resolver::{ TokioAsyncResolver as AsyncResolver, TokioHandle };
use trust_dns_resolver::config::{ ResolverConfig, ResolverOpts, NameServerConfigGroup };
use anyhow::format_err;
use argh::FromArgs;
use directories::ProjectDirs;
use mitmca::{ Entry, CertStore };
use httptunnel::Proxy;
use crate::config::Config;


/// No SNI local proxy
#[derive(FromArgs)]
#[argh(subcommand, name = "proxy")]
pub struct Options {
    /// config path
    #[argh(option, short = 'c')]
    config: Option<PathBuf>,
}

impl Options {
    pub async fn exec(self) -> anyhow::Result<()> {
        let config_path = self.config
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

        let resolver = if let Some(doh) = config.doh {
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
            tls_config.alpn_protocols = vec![b"h2".to_vec()];
            tls_config.enable_sni = doh.sni;
            tls_config.enable_early_data = true;
            let tls_config = Arc::new(tls_config);

            let server = NameServerConfigGroup::from_ips_https(
                &[doh.addr.ip()], doh.addr.port(),
                doh.name, false
            );
            let mut config = ResolverConfig::from_parts(None, Vec::new(), server);
            config.set_tls_client_config(tls_config);

            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(2);
            opts.attempts = 1;

            #[cfg(feature = "dnssec")] {
                opts.validate = doh.dnssec;
            }

            AsyncResolver::new(config, opts, TokioHandle)?
        } else {
            AsyncResolver::from_system_conf(TokioHandle)?
        };

        let forward = Arc::new(Proxy {
            ca, resolver,
            alpn: config.alpn,
            mapping: config.mapping,
            hosts: config.hosts.unwrap_or_default(),
            handle: tokio::runtime::Handle::current()
        });

        let make_service = make_service_fn(|_| {
            let forward = forward.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| httptunnel::proxy_call(forward.clone(), req)))
            }
        });

        let srv = Server::bind(&addr)
            .serve(make_service);
        println!("bind: {:?}", srv.local_addr());
        srv.await.map_err(anyhow::Error::from)
    }
}

fn read_root_cert(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertStore> {
    let cert_buf = fs::read_to_string(cert_path)?;
    let key_buf = fs::read_to_string(key_path)?;
    let entry = Entry::from_pem(&cert_buf, &key_buf)?;
    Ok(CertStore::from(entry))
}
