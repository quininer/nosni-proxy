use std::fs;
use std::io::{ self, Write };
use std::sync::Arc;
use std::path::PathBuf;
use std::time::Duration;
use std::convert::TryFrom;
use std::net::SocketAddr;
use futures::future::TryFutureExt;
use tokio::net::TcpStream;
use tokio_rustls::{ rustls, TlsConnector };
use hyper::{ header, Uri, Body, Method, Request };
use hyper::body::HttpBody;
use hyper::client::conn;
use trust_dns_resolver::{ TokioAsyncResolver as AsyncResolver, TokioHandle };
use trust_dns_resolver::config::{ ResolverConfig, ResolverOpts, NameServerConfigGroup };
use directories::ProjectDirs;
use argh::FromArgs;
use anyhow::Context;
use crate::config::Config;


/// No SNI checker
#[derive(FromArgs)]
#[argh(subcommand, name = "check")]
pub struct Options {
    /// check target
    #[argh(positional)]
    target: Uri,

    /// specify addr
    #[argh(option, short = 'a')]
    addr: Option<SocketAddr>,

    /// specify user agent
    #[argh(option, short = 'u')]
    user_agent: Option<header::HeaderValue>,

    /// custom SNI, default empty
    #[argh(option, short = 's')]
    sni: Option<String>,

    /// config path
    #[argh(option, short = 'c')]
    config: Option<PathBuf>,

    /// force no sni
    #[argh(switch)]
    force_no_sni: bool,

    /// show body
    #[argh(switch)]
    show_body: bool
}

impl Options {
    pub async fn exec(self) -> anyhow::Result<()> {
        let resolver = {
            let config_path = self.config
                .clone()
                .or_else(|| {
                    ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
                        .map(|dir| dir.config_dir().join("config.toml"))
                })
                .context("missing config")?;
            let config: Config = toml::from_str(&fs::read_to_string(&config_path)?)?;

            if let Some(ref doh) = config.doh {
                let mut root_cert_store = tokio_rustls23::rustls::RootCertStore::empty();
                root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                    |ta| {
                        tokio_rustls23::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    },
                ));
                let mut tls_config = tokio_rustls23::rustls::ClientConfig::builder()
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

                AsyncResolver::new(dns_config, opts, TokioHandle)?
            } else {
                AsyncResolver::from_system_conf(TokioHandle)?
            }
        };

        let addr = if let Some(addr) = self.addr {
            addr
        } else {
            let host = self.target.host().context("not found host")?;
            let ips = resolver.lookup_ip(host).await?;
            let ip = ips.iter().next().context("not found addr")?;
            (ip, self.target.port_u16().unwrap_or(443)).into()
        };
        let sni = self.sni
            .as_ref()
            .map(String::as_str)
            .or_else(|| self.target.host())
            .and_then(|host| rustls::ServerName::try_from(host).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

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
        tls_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
        tls_config.enable_sni = if self.force_no_sni {
            false
        } else {
            self.sni.is_some()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));

        let mut request = Request::new(Body::empty());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = self.target.clone();
        if let Some(ua) = self.user_agent.clone() {
            request.headers_mut()
                .insert(header::USER_AGENT, ua);
        }

        let stream = TcpStream::connect(&addr).await?;
        let stream = connector.connect(sni, stream).await?;

        let mut builder = conn::Builder::new();
        let (_, session) = stream.get_ref();
        if let Some(b"h2") = session.alpn_protocol() {
            builder.http2_only(true);
        }
        let (mut sender, conn) = builder.handshake::<_, Body>(stream)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            .await?;

        tokio::spawn(conn.map_err(|err| eprintln!("conn error: {:?}", err)));

        let response = sender.send_request(request)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            .await?;

        let (parts, mut body) = response.into_parts();
        println!("parts:\n {:#?}", parts);

        if self.show_body {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();

            while let Some(data) = body.data().await {
                let data = data?;
                stdout.write_all(&data)?;
            }

            stdout.flush()?;
        }

        Ok(())
    }
}
