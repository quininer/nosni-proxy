mod socks5;
mod mitm;
mod fragment;
mod localdoh;

use std::fs;
use std::time::Duration;
use std::sync::Arc;
use std::path::{ PathBuf, Path };
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::sync::Mutex;
use hickory_resolver::config::{ ResolverConfig, NameServerConfigGroup };
use anyhow::format_err;
use argh::FromArgs;
use directories::ProjectDirs;
use mitmca::{ Entry, CertStore };
use crate::config::Config;


/// No SNI local proxy
#[derive(FromArgs)]
#[argh(subcommand, name = "proxy")]
pub struct Options {
    /// config path
    #[argh(option, short = 'c')]
    config: Option<PathBuf>,
}

struct Shared {
    config: Config,
    resolver: hickory_resolver::TokioResolver,
}

impl Options {
    pub async fn exec(self) -> anyhow::Result<()> {
        let config_path = self.config
            .or_else(|| {
                ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
                    .map(|dir| dir.config_dir().join("config.toml"))
            })
            .ok_or_else(|| format_err!("missing config"))?;

        let shared = {
            let config: Config = toml::from_str(&fs::read_to_string(&config_path)?)?;

            let resolver = if let Some(ref doh) = config.doh {
                use tokio_rustls::rustls;

                let mut root_cert_store = rustls::RootCertStore::empty();
                root_cert_store.roots = webpki_roots::TLS_SERVER_ROOTS.into();
                let mut tls_config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth();                
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
                tls_config.enable_sni = doh.sni;
                tls_config.enable_early_data = true;

                let server = NameServerConfigGroup::from_ips_https(
                    &[doh.addr.ip()], doh.addr.port(),
                    doh.name.clone(), false
                );
                let dns_config = ResolverConfig::from_parts(None, Vec::new(), server);

                let mut builder = hickory_resolver::Resolver::builder_with_config(
                    dns_config,
                    hickory_resolver::name_server::TokioConnectionProvider::default()
                );
                builder.options_mut().tls_config = tls_config;
                builder.options_mut().timeout = Duration::from_secs(2);
                builder.options_mut().attempts = 1;

                #[cfg(feature = "dnssec")] {
                    builder.options_mut().validate = doh.dnssec;
                }

                builder.build()
            } else {
                hickory_resolver::TokioResolver::builder_tokio()?.build()
            };

            Arc::new(Shared { config, resolver })
        };

        let mut maybe_ca = None;
        let mut joinset: JoinSet<anyhow::Result<()>> = JoinSet::new();

        if let Some(config) = shared.config.mitm.as_ref() {
            let proxy = {
                let cert_path = config_path
                    .parent()
                    .unwrap_or(&config_path)
                    .join(&config.cert);
                let key_path = config_path
                    .parent()
                    .unwrap_or(&config_path)
                    .join(&config.key);
                let ca = Arc::new(Mutex::new(read_root_cert(&cert_path, &key_path)?));
                maybe_ca = Some(ca.clone());

                mitm::Proxy { ca, shared: shared.clone() }
            };
            let listener = TcpListener::bind(config.bind).await?;

            println!("mitm listen: {:?}", listener.local_addr());

            joinset.spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await?;
                    let req_id: u64 = rand::random();
                    let proxy = proxy.clone();
                    tokio::spawn(async move {
                        if let Err(err) = proxy.call(req_id, stream).await {
                            eprintln!("[{:x}] proxy connect error: {:?}", req_id, err)
                        }
                    });
                }
            });
        }

        if let Some(config) = shared.config.fragment.clone() {
            let listener = TcpListener::bind(&config.bind).await?;
            let proxy = Arc::new(fragment::Proxy { config, shared: shared.clone() });

            println!("fragment listen: {:?}", listener.local_addr());

            joinset.spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await?;
                    let req_id: u64 = rand::random();
                    let proxy = proxy.clone();
                    tokio::spawn(async move {
                        if let Err(err) = proxy.call(req_id, stream).await {
                            eprintln!("[{:x}] fragment connect error: {:?}", req_id, err)
                        }
                    });
                }
            });
        }

        if let Some(((localdoh_config, doh_config), ca)) = shared.config.localdoh.as_ref()
            .zip(shared.config.doh.as_ref())
            .zip(maybe_ca)
        {
            let listener = TcpListener::bind(&localdoh_config.bind).await?;
            let proxy = localdoh::Proxy::new(ca, localdoh_config, doh_config).await?;
            let proxy = Arc::new(proxy);

            println!("localdoh listen: {:?}", listener.local_addr());

            joinset.spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await?;
                    let req_id: u64 = rand::random();
                    let proxy = proxy.clone();
                    tokio::spawn(async move {
                        if let Err(err) = proxy.call(req_id, stream).await {
                            eprintln!("[{:x}] localdoh proxy error: {:?}", req_id, err)
                        }
                    });
                }
            });
        }

        while let Some(result) = joinset.join_next().await {
            let () = result??;
        }

        Ok(())
    }
}

fn read_root_cert(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertStore> {
    let cert_buf = fs::read_to_string(cert_path)?;
    let key_buf = fs::read_to_string(key_path)?;
    let entry = Entry::from_pem(&cert_buf, &key_buf)?;
    Ok(CertStore::from(entry))
}
