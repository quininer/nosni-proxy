use std::io;
use std::sync::Arc;
use std::net::{ SocketAddr, ToSocketAddrs };
use futures_util::future::TryFutureExt;
use tokio::net::TcpStream;
use tokio_rustls::{ webpki, rustls, TlsConnector };
use tokio_rustls::rustls::Session;
use hyper::{ header, Uri, Body, Method, Request };
use hyper::client::conn;
use structopt::StructOpt;


#[derive(StructOpt)]
struct Options {
    /// Check target
    target: Uri,

    /// Specify addr
    #[structopt(short="a", long="addr")]
    addr: Option<SocketAddr>,

    /// Specify user agent
    #[structopt(short="u", long="user-agent")]
    user_agent: Option<header::HeaderValue>,

    /// Custom SNI, default empty
    #[structopt(short="s", long="sni")]
    sni: Option<String>
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let options = Options::from_args();

    let addr = options.addr
        .or_else(|| options.target.host()
            .and_then(|host| (host, options.target.port_u16().unwrap_or(443))
                .to_socket_addrs().ok()?
                .next()
            )
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not found addr"))?;
    let sni = options.sni
        .as_ref()
        .map(String::as_str)
        .or_else(|| options.target.host())
        .and_then(|host| webpki::DNSNameRef::try_from_ascii_str(host).ok())
        .map(|dnsname| dnsname.to_owned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

    let mut tls = rustls::ClientConfig::new();
    tls.enable_sni = options.sni.is_some();
    tls.set_protocols(&["h2".into(), "http/1.1".into()]);
    tls.root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let connector = TlsConnector::from(Arc::new(tls));

    let mut request = Request::new(Body::empty());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = options.target.clone();
    if let Some(ua) = options.user_agent.clone() {
        request.headers_mut()
            .insert(header::USER_AGENT, ua);
    }

    let stream = TcpStream::connect(&addr).await?;
    let stream = connector.connect(sni.as_ref(), stream).await?;

    let mut builder = conn::Builder::new();
    let (_, session) = stream.get_ref();
    if let Some(b"h2") = session.get_alpn_protocol() {
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
