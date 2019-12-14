use std::pin::Pin;
use std::future::Future;
use std::sync::{ Arc, Mutex };
use std::collections::HashMap;
use futures::future;
use tokio::runtime::Handle;
use hyper::{ Method, StatusCode, Request, Response, Body };
use trust_dns_resolver::AsyncResolver;
use mitmca::CertStore;
use crate::httptunnel;


#[derive(Clone)]
pub struct Proxy {
    pub alpn: Option<String>,
    pub ca: Arc<Mutex<CertStore>>,
    pub resolver: AsyncResolver,
    pub mapping: HashMap<String, String>,
    pub hosts: HashMap<String, String>,
    pub handle: Handle
}

pub type BoxedFuture =
    Pin<Box<dyn Future<Output = hyper::Result<Response<Body>>> + 'static + Send>>;

pub fn call(proxy: Arc<Proxy>, req: Request<Body>)
    -> BoxedFuture
{
    println!(">> {:?}", (req.uri().host(), req.uri().port_u16()));

    if Method::CONNECT == req.method() {
        match httptunnel::call(&proxy, req) {
            Ok(resp) => resp,
            Err(err) => {
                eprintln!("call: {:?}", err);
                let mut resp = Response::new(Body::empty());
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Box::pin(future::ok(resp))
            }
        }
    } else {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        Box::pin(future::ok(resp))
    }
}
