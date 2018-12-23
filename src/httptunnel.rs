use std::net::SocketAddr;
use failure::{ Fallible, err_msg };
use tokio::prelude::*;
use tokio::io as aio;
use tokio::net::TcpStream;
use openssl::ssl::{ SslMethod, SslConnector, AlpnError };
use tokio_openssl::{ ConnectConfigurationExt, SslAcceptorExt };
use hyper::{ StatusCode, Request, Response, Body };
use hyper::service::Service;
use percent_encoding::percent_decode;
use crate::proxy::Proxy;


macro_rules! and {
    ( $fut:expr, $( $t:expr ),+ ) => {
        $fut.map(move |x| (x, $( $t ),+))
    }
}


pub fn call(proxy: &mut Proxy, req: Request<<Proxy as Service>::ReqBody>)
    -> Fallible<<Proxy as Service>::Future>
{
    let Proxy { alpn, ca, resolver } = proxy;
    let ca = ca.clone();
    let resolver = resolver.clone();
    let port = req.uri().port().unwrap_or(443);
    let maybe_alpn = req.headers()
        .get("ALPN")
        .and_then(|val| val.to_str().ok())
        .or_else(|| alpn.as_ref().map(String::as_str));

    let mut tls_builder = SslConnector::builder(SslMethod::tls())?;
    if let Some(val) = maybe_alpn {
        let alpn = val.split(',')
            .filter_map(|protocol| percent_decode(protocol.trim().as_bytes())
                .decode_utf8()
                .ok())
            .fold(Vec::new(), |mut sum, next| {
                let next = next.as_bytes();
                sum.push(next.len() as u8);
                sum.extend_from_slice(next);
                sum
            });
        tls_builder.set_alpn_protos(&alpn)?;
    }
    let connector = tls_builder.build()
        .configure()?
        .use_server_name_indication(false);

    let done = req.uri().host()
        .map(ToOwned::to_owned)
        .ok_or_else(|| err_msg("missing host"))
        .into_future()
        .map(move |name| {
            let fut = req.into_body()
                .on_upgrade()
                .map_err(failure::Error::from)
                .and_then(move |upgraded| {
                    let fut = resolver.lookup_ip(name.as_str())
                        .map_err(Into::into)
                        .and_then(|lookup| lookup.iter()
                            .next()
                            .ok_or_else(|| err_msg("ip not found")))
                        .and_then(move |ip| {
                            eprintln!(">>> {:?}", ip);
                            let addr = SocketAddr::from((ip, port));
                            TcpStream::connect(&addr)
                                .map_err(Into::into)
                                .and_then(move |remote| {
                                    let fut = connector.connect_async(&name, remote)
                                        .map_err(Into::into);
                                    and!(fut, name)
                                })
                        });
                    and!(fut, upgraded)
                })
                .and_then(move |((remote, name), upgraded)| {
                    let mut builder = ca.lock()
                        .map_err(|_| err_msg("deadlock"))?
                        .get(&name)?;
                    if let Some(protocol) = remote.get_ref().ssl()
                        .selected_alpn_protocol()
                        .map(ToOwned::to_owned)
                    {
                        builder.set_alpn_select_callback(move |_, buf|
                            alpn_select_callback(&protocol, buf)
                        );
                    }
                    let acceptor = builder.build();
                    Ok((acceptor, remote, upgraded))
                })
                .and_then(|(acceptor, remote, upgraded)| {
                    let fut = acceptor.accept_async(upgraded).map_err(Into::into);
                    and!(fut, remote)
                })
                .and_then(|(local, remote)| {
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
            let mut resp = Response::new(Body::from(format!("{:?}", err)));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(resp)
        });

    Ok(Box::new(done))
}

#[no_panic::no_panic]
fn alpn_select_callback<'a>(protocol: &[u8], buf: &'a [u8]) -> Result<&'a [u8], AlpnError> {
    let mut index = 0;
    while index < buf.len() {
        let n = buf.get(index)
            .map(|&n|n as usize)
            .ok_or(AlpnError::ALERT_FATAL)?;
        index += 1;
        let protocol2 = buf
            .get(index..index + n)
            .ok_or(AlpnError::ALERT_FATAL)?;
        if protocol == protocol2 {
            return Ok(protocol2);
        }
        index += n;
    }
    Err(AlpnError::NOACK)
}
