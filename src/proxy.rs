use std::sync::Arc;
use tokio::prelude::*;
use hyper::{ Method, Request, Response, Body };
use hyper::service::Service;
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;
use crate::{ httpfwd, httptunnel };


#[derive(Clone)]
pub struct Proxy {
    pub tls: Arc<HttpsConnector<HttpConnector>>
}

impl Service for Proxy {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response<Self::ResBody>, Error=Self::Error> + 'static + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        if Method::CONNECT == req.method() {
            httptunnel::call(self, req)
        } else {
            httpfwd::call(self, req)
        }
    }
}
