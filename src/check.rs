use std::io;
use std::sync::Arc;
use std::convert::TryFrom;
use std::net::{ SocketAddr, ToSocketAddrs };
use futures::future::TryFutureExt;
use tokio::net::TcpStream;
use tokio_rustls::{ rustls, TlsConnector };
use hyper::{ header, Uri, Body, Method, Request };
use hyper::client::conn;
use argh::FromArgs;


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
    sni: Option<String>
}

impl Options {
    pub async fn exec(self) -> anyhow::Result<()> {
        let addr = self.addr
            .or_else(|| self.target.host()
                .and_then(|host| (host, self.target.port_u16().unwrap_or(443))
                    .to_socket_addrs().ok()?
                    .next()
                )
            )
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not found addr"))?;
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
        tls_config.enable_sni = self.sni.is_some();

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

        let (parts, _) = response.into_parts();
        println!("parts:\n {:#?}", parts);

        Ok(())
    }
}
