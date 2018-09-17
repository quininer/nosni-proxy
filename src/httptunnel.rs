use std::net::SocketAddr;
use failure::err_msg;
use tokio::prelude::*;
use tokio::io as aio;
use tokio::net::TcpStream;
use tokio_tls::{ TlsConnector, TlsAcceptor };
use hyper::{ Request, Response, Body };
use hyper::service::Service;
use crate::proxy::Proxy;


macro_rules! and {
    ( $fut:expr, $( $t:expr ),+ ) => {
        $fut.map(move |x| (x, $( $t ),+))
    }
}


pub fn call(proxy: &mut Proxy, req: Request<<Proxy as Service>::ReqBody>)
    -> <Proxy as Service>::Future
{
    let Proxy { tls, serv, resolver, .. } = proxy;
    let tls = TlsConnector::from(tls.clone());
    let serv = TlsAcceptor::from(serv.clone());
    let resolver = resolver.clone();
    let port = req.uri().port().unwrap_or(443);

    let done = req.uri().host()
        .map(ToOwned::to_owned)
        .ok_or_else(|| err_msg("Missing Host"))
        .into_future()
        .and_then(move |name| {
            let fut = resolver.lookup_ip(name.as_str())
                .map_err(Into::into)
                .and_then(|lookup| lookup.iter()
                    .next()
                    .ok_or_else(|| err_msg("ip not found"))
                );
            and!(fut, name)
        })
        .map(move |(ip, name)| {
            let fut = req.into_body()
                .on_upgrade()
                .map_err(failure::Error::from)
                .and_then(move |upgraded| serv.accept(upgraded).map_err(Into::into))
                .and_then(move |local| {
                    let addr = SocketAddr::from((ip, port));

                    let fut = TcpStream::connect(&addr)
                        .map_err(Into::into)
                        .and_then(move |remote| tls.connect(&name, remote)
                            .map_err(Into::into)
                        );

                    and!(fut, local)
                })
                .and_then(|(remote, local)| {
                    let (remote_read, remote_write) = remote.split();
                    let (local_read, local_write) = local.split();

                    aio::copy(remote_read, local_write)
                        .map(drop)
                        .select2(aio::copy(local_read, remote_write).map(drop))
                        .map(drop)
                        .map_err(|res| res.split().0.into())
                })
                .map_err(|err| eprintln!("{:?}", err));

            hyper::rt::spawn(fut);

            Response::new(Body::empty())
        })
        .or_else(|err| {
            Ok(Response::builder()
                .status(400)
                .body(Body::from(format!("{:?}", err)))
                .unwrap()
            )
        });

    Box::new(done)
}
