use tokio::prelude::*;
use hyper::{ Method, Request, Response, Body };
use hyper::service::Service;
use hyper::client::HttpConnector;
use native_tls::{ TlsConnector, TlsAcceptor };
use trust_dns_resolver::AsyncResolver;
use crate::{ httpfwd, httptunnel };


#[derive(Clone)]
pub struct Proxy {
    pub http: HttpConnector,
    pub tls: TlsConnector,
    pub serv: TlsAcceptor,
    pub resolver: AsyncResolver
}

impl Service for Proxy {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response<Self::ResBody>, Error=Self::Error> + 'static + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        eprintln!(">> {:?}", (req.uri().host(), req.uri().port()));
        eprintln!("{:#?}", req);

        if Method::CONNECT == req.method() {
            httptunnel::call(self, req)
        } else {
            httpfwd::call(self, req)
        }
    }
}
