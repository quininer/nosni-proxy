use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use mitmca::CertStore;
use crate::proxy::Shared;
use crate::util::{ ZlibDecompressor, ZstdDecompressor, LOCAL_SESSION_CACHE, REMOTE_SESSION_CACHE };


#[derive(Clone)]
pub struct Proxy {
    pub ca: Arc<Mutex<CertStore>>,
    pub shared: Arc<Shared>
}

impl Proxy {
    pub async fn call(self, req_id: u64, stream: TcpStream) -> anyhow::Result<()> {
        use tokio_rustls::rustls;
        use tokio_rustls::{ TlsConnector, TlsAcceptor };

        let localdoh_config = self.shared.config.localdoh.as_ref().context("must localdoh config")?;
        let doh_config = self.shared.config.doh.as_ref().context("must doh config")?;

        let mut local = {
            let mut tls_config = self.ca.lock().await.get(&localdoh_config.name)?;
            tls_config.session_storage = LOCAL_SESSION_CACHE.clone();
            tls_config.alpn_protocols = vec![b"h2".into()];
            let acceptor = TlsAcceptor::from(Arc::new(tls_config));
            acceptor.accept(stream).await?
        };        

        println!("[{:x}] start connect: {:?}", req_id, doh_config.addr);

        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.roots = webpki_roots::TLS_SERVER_ROOTS.into();
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h2".into()];
        tls_config.enable_sni = doh_config.sni;
        tls_config.resumption = REMOTE_SESSION_CACHE.clone();
        tls_config.cert_decompressors = vec![&ZlibDecompressor, &ZstdDecompressor];

        let connector = TlsConnector::from(Arc::new(tls_config));
        let remote = TcpStream::connect(doh_config.addr).await?;

        let dnsname = rustls::pki_types::ServerName::try_from(doh_config.name.as_str())
            .map_err(|_| anyhow::format_err!("bad dnsname: {:?}", doh_config.name))?;
        let mut remote = connector.connect(dnsname.to_owned(), remote).await?;

        println!("[{:x}] connected: {:?}", req_id, remote.get_ref().0.peer_addr());

        copy_bidirectional(&mut local, &mut remote)
            .await
            .map(drop)
            .context("bidirectional copy stream error")?;

        Ok(())        
    }
}
