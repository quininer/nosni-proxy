use std::sync::Arc;
use std::net::SocketAddr;

use futures::TryFutureExt;
use tokio::sync::Mutex;
use tokio::net::TcpStream;
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{ TokioExecutor, TokioTimer, TokioIo };
use tokio_rustls::{ rustls, TlsConnector, TlsAcceptor };

use mitmca::CertStore;
use crate::config::{Doh, LocalDoh};
use crate::util::{ ZlibDecompressor, ZstdDecompressor, LOCAL_SESSION_CACHE, REMOTE_SESSION_CACHE };


pub struct Proxy {
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    dnsaddr: SocketAddr,
    dnsname: rustls::pki_types::ServerName<'static>,
    hostname: http::uri::Authority,
    server: hyper::server::conn::http2::Builder<TokioExecutor>,
    client: hyper::client::conn::http2::Builder<TokioExecutor>,
    send_req: Mutex<Option<SendRequest<Incoming>>>,
}

impl Proxy {
    pub async fn new(ca: Arc<Mutex<CertStore>>, localdoh_config: &LocalDoh, doh_config: &Doh)
        -> anyhow::Result<Self>
    {        
        let acceptor = {
            let mut tls_config = ca.lock().await.get(&localdoh_config.name)?;
            tls_config.session_storage = LOCAL_SESSION_CACHE.clone();
            tls_config.alpn_protocols = vec![b"h2".into()];
            TlsAcceptor::from(Arc::new(tls_config))
        };

        let connector = {
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.roots = webpki_roots::TLS_SERVER_ROOTS.into();
            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            tls_config.alpn_protocols = vec![b"h2".into()];
            tls_config.enable_sni = doh_config.sni;
            tls_config.enable_early_data = true;
            tls_config.resumption = REMOTE_SESSION_CACHE.clone();
            tls_config.cert_decompressors = vec![&ZlibDecompressor, &ZstdDecompressor];
            TlsConnector::from(Arc::new(tls_config))
        };

        let dnsname = rustls::pki_types::ServerName::try_from(doh_config.name.as_str())
            .map_err(|_| anyhow::format_err!("bad dnsname: {:?}", doh_config.name))?;

        let mut server = hyper::server::conn::http2::Builder::new(TokioExecutor::default());
        server.timer(TokioTimer::new());
        let mut client = hyper::client::conn::http2::Builder::new(TokioExecutor::default());
        client.timer(TokioTimer::new());

        Ok(Proxy {
            acceptor,
            connector,
            server,
            client,
            dnsaddr: doh_config.addr,
            dnsname: dnsname.to_owned(),
            hostname: http::uri::Authority::from_maybe_shared(doh_config.name.clone())?,
            send_req: Mutex::new(None)
        })
    }
    
    pub async fn call(self: Arc<Self>, req_id: u64, stream: TcpStream) -> anyhow::Result<()> {
        async fn call(proxy: &Proxy, req_id: u64, mut req: http::Request<Incoming>)
            -> anyhow::Result<http::Response<Incoming>>
        {
            let mut parts = req.uri().clone().into_parts();
            parts.authority = Some(proxy.hostname.clone());
            *req.uri_mut() = http::Uri::from_parts(parts)?;
                        
            let mut send_req = proxy.send_req.lock().await;

            if let Some(send_req2) = send_req.as_ref() {
                if send_req2.is_closed() {
                    *send_req = None;
                }
            }

            if send_req.is_none() {
                let remote = TcpStream::connect(&proxy.dnsaddr).await?;
                remote.set_nodelay(true)?;
                let remote = proxy.connector.connect(proxy.dnsname.to_owned(), remote).await?;
                remote.get_ref().0.set_nodelay(false)?;

                println!("[{}] new remote doh connect: {:?}", req_id, remote.get_ref().0.peer_addr());

                let (send_req2, conn) = proxy.client.handshake::<_, Incoming>(TokioIo::new(remote)).await?;
                tokio::spawn(conn.map_err(move |err| eprintln!("[{}] remote http2 error: {:?}", req_id, err)));
                
                *send_req = Some(send_req2);
            }

            let mut send_req2 = send_req.take().unwrap();
            let resp = send_req2.send_request(req).await?;
            *send_req = Some(send_req2);
            
            Ok(resp) as anyhow::Result<http::Response<_>>
        }

        let svc = hyper::service::service_fn(|req| {
            let proxy = self.clone();
            async move {
                call(&proxy, req_id, req).await
            }
        });

        let local = self.acceptor.accept(stream).await?;

        println!("[{:x}] start serve: {:?}", req_id, local.get_ref().0.local_addr());

        if let Err(err) = self.server.serve_connection(TokioIo::new(local), svc).await {
            eprintln!("[{}] local http2 error: {:?}", req_id, err);
        }

        Ok(())        
    }
}
