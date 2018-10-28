use tokio::prelude::*;
use hyper::{ Method, StatusCode, Request, Response, Body };
use hyper::service::Service;
use hyper::client::HttpConnector;
use native_tls::{ TlsConnector, TlsAcceptor };
use trust_dns_resolver::AsyncResolver;
use crate::{ httpfwd, httptunnel };


#[derive(Clone)]
pub struct Proxy {
    pub alpn: Option<String>,
    pub http: HttpConnector,
    pub serv: TlsAcceptor,
    pub resolver: AsyncResolver
}

impl Service for Proxy {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response<Self::ResBody>, Error=Self::Error> + 'static + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        println!(">> {:?}", (req.uri().host(), req.uri().port()));

        if Method::CONNECT == req.method() {
            match httptunnel::call(self, req) {
                Ok(resp) => resp,
                Err(err) => {
                    let mut resp = Response::new(Body::empty());
                    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    Box::new(future::ok(resp))
                }
            }
        } else {
            httpfwd::call(self, req)
        }
    }
}
