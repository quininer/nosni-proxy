mod socks5;

use std::fs;
use std::time::Duration;
use std::sync::Arc;
use std::path::{ PathBuf, Path };
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::rustls;
use trust_dns_resolver::TokioAsyncResolver as AsyncResolver;
use trust_dns_resolver::config::{ ResolverConfig, ResolverOpts, NameServerConfigGroup };
use anyhow::format_err;
use argh::FromArgs;
use directories::ProjectDirs;
use mitmca::{ Entry, CertStore };
use socks5::Proxy;
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
        let proxy = {
            let config_path = self.config
                .or_else(|| {
                    ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
                        .map(|dir| dir.config_dir().join("config.toml"))
                })
                .ok_or_else(|| format_err!("missing config"))?;
            let config: Config = toml::from_str(&fs::read_to_string(&config_path)?)?;

            let cert_path = config_path
                .parent()
                .unwrap_or(&config_path)
                .join(&config.cert);
            let key_path = config_path
                .parent()
                .unwrap_or(&config_path)
                .join(&config.key);
            let ca = Arc::new(Mutex::new(read_root_cert(&cert_path, &key_path)?));

            let resolver = if let Some(ref doh) = config.doh {
                let mut root_cert_store = rustls::RootCertStore::empty();
                root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
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
                    doh.name.clone(), false
                );
                let mut dns_config = ResolverConfig::from_parts(None, Vec::new(), server);
                dns_config.set_tls_client_config(tls_config);

                let mut opts = ResolverOpts::default();
                opts.timeout = Duration::from_secs(2);
                opts.attempts = 1;

                #[cfg(feature = "dnssec")] {
                    opts.validate = doh.dnssec;
                }

                AsyncResolver::tokio(dns_config, opts)
            } else {
                AsyncResolver::tokio_from_system_conf()?
            };

            Arc::new(Proxy { ca, resolver, config })
        };

        let listener = TcpListener::bind(proxy.config.bind).await?;

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
    }
}

fn read_root_cert(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertStore> {
    let cert_buf = fs::read_to_string(cert_path)?;
    let key_buf = fs::read_to_string(key_path)?;
    let entry = Entry::from_pem(&cert_buf, &key_buf)?;
    Ok(CertStore::from(entry))
}
