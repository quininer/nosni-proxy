use std::io;
use std::sync::Arc;
use std::net::{ SocketAddr, IpAddr, Ipv4Addr };
use std::time::Duration;
use anyhow::Context;

use tokio::io::copy_bidirectional;
use tokio::io::{ AsyncReadExt, AsyncWriteExt };
use tokio::time::{ sleep, timeout };
use tokio::net::TcpStream;

use futures::future::{ self, FutureExt, TryFutureExt };
use futures::stream::{ self, StreamExt };
use tower_layer::Layer;
use tower_util::{ service_fn, ServiceExt };
use tower_happy_eyeballs::HappyEyeballsLayer;

use crate::config::{ StrOrList, Fragment };
use crate::proxy::{ socks5, Shared };


#[derive(Clone)]
pub struct Proxy {
    pub config: Fragment,
    pub shared: Arc<Shared>
}

impl Proxy {
    pub async fn call(self, req_id: u64, mut stream: TcpStream) -> anyhow::Result<()> {
        // local handshake
        //
        // Get target addr
        let addr = socks5::handshake(&mut stream)
            .await
            .context("socks5 handshake")?;

        println!("[{:x}] start connect: {:?}", req_id, addr);

        let maybe_remote = match &addr {
            socks5::Address::Addr(addr) => TcpStream::connect(addr).await.context("remote connect with address"),
            socks5::Address::Domain(hostname, port) => {
                let lookup = match self.shared.config.mapping.get(hostname)
                    .and_then(|rule| rule.addr.as_ref())
                {
                    Some(StrOrList::Str(name)) => self.shared.resolver.lookup_ip(name)
                        .map_ok(|ips| ips.into_iter().collect::<Vec<_>>())
                        .boxed(),
                    Some(StrOrList::List(list)) => future::ready(Ok(list.clone())).boxed(),
                    None => self.shared.resolver.lookup_ip(hostname.clone())
                        .map_ok(|ips| ips.into_iter().collect::<Vec<_>>())
                        .boxed()
                };

                let ips = timeout(Duration::from_secs(5), lookup).await
                    .map_err(anyhow::Error::from)
                    .and_then(|ret| ret.map_err(anyhow::Error::from))
                    .with_context(|| format!("dns lookup failure: {}", hostname))?;

                remote_connect(ips, *port).await.context("remote connect")
            }
        };

        let mut remote = match maybe_remote {
            Ok(remote) => {
                let addr = remote.local_addr().context("get remote local addr failed")?;
                socks5::response(&mut stream, 0, addr).await.context("socks5 response")?;
                remote
            },
            Err(err) => {
                let reply = err.chain()
                    .find(|err| {
                        let kind = err.downcast_ref::<io::Error>().map(|err| err.kind());
                        kind == Some(io::ErrorKind::ConnectionRefused)
                    })
                    .map(|_| 5)
                    .unwrap_or(1);

                let maybe_addr = match addr {
                    socks5::Address::Addr(addr) => addr,
                    socks5::Address::Domain(_, port) => SocketAddr::from((Ipv4Addr::LOCALHOST, port))
                };
                socks5::response(&mut stream, reply, maybe_addr).await.context("socks5 response")?;
                return Err(err);
            }
        };

        let mut header = [0; 5];
        stream.read_exact(&mut header).await?;

        let ty = header[0];
        let ver = u16::from_be_bytes([header[1], header[2]]);
        let len = u16::from_be_bytes([header[3], header[4]]);

        if ty == HANDSHAKE_TYPE && ver & 0xff00 == TLS {
            let mut hello = vec![0; len.into()];
            stream.read_exact(&mut hello).await?;

            let mut pos = 0;

            while hello.len() > pos {
                let len = hello.len() - pos;
                let len = len.try_into().context("bad length")?;
                let (len, dur) = fragment(len, &self.config);

                let mut header = header;
                header[3..].copy_from_slice(&len.to_be_bytes());

                remote.write_all(&header).await?;
                remote.write_all(&hello[pos..][..len.into()]).await?;
                pos += usize::from(len);
                remote.flush().await?;

                if let Some(dur) = dur {
                    sleep(dur).await;
                }
            }
        } else {
            remote.write_all(&header).await?;
        }

        println!("[{:x}] connected: {:?}", req_id, remote.peer_addr());

        copy_bidirectional(&mut stream, &mut remote)
            .await
            .map(drop)
            .context("bidirectional copy stream error")?;

        Ok(())
    }
}

const HANDSHAKE_TYPE: u8 = 0x16;
const TLS: u16 = 0x0300;

pub async fn remote_connect<I>(ips: I, port: u16)
    -> anyhow::Result<TcpStream>
where
    I: IntoIterator<Item = IpAddr>
{
    let make_conn = service_fn(|ip| TcpStream::connect((ip, port)));

    let remote = HappyEyeballsLayer::new()
        .layer(make_conn)
        .oneshot(stream::iter(ips).fuse()).await?;

    Ok(remote)
}

fn fragment(len: u16, config: &Fragment) -> (u16, Option<Duration>) {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    let len = {
        let start = std::cmp::min(len, config.size.0);
        let end = std::cmp::min(len, config.size.1);
        rng.gen_range(start..=end)
    };
    let dur = config.delay.map(|delay| {
        let start = std::cmp::min(delay.0, delay.1);
        let end = std::cmp::max(delay.0, delay.1);
        Duration::from_millis(rng.gen_range(start..=end))
    });

    (len, dur)
}
