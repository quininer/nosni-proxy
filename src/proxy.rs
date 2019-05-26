use std::sync::{ Arc, Mutex };
use std::collections::HashMap;
use tokio::prelude::*;
use hyper::{ Method, StatusCode, Request, Response, Body };
use hyper::service::Service;
use trust_dns_resolver::AsyncResolver;
use mitmca::CertStore;
use crate::httptunnel;


#[derive(Clone)]
pub struct Proxy {
    pub alpn: Option<String>,
    pub ca: Arc<Mutex<CertStore>>,
    pub resolver: AsyncResolver,
    pub mapping: HashMap<String, Option<String>>
}

impl Service for Proxy {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response<Self::ResBody>, Error=Self::Error> + 'static + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        println!(">> {:?}", (req.uri().host(), req.uri().port_u16()));

        if Method::CONNECT == req.method() {
            if let Ok(resp) = httptunnel::call(self, req) {
                return resp;
            }
        }

        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        Box::new(future::ok(resp))
    }
}
