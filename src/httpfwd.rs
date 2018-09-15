use std::sync::Arc;
use http::uri::{ Scheme, PathAndQuery };
use http::header::HeaderName;
use tokio::prelude::*;
use hyper::{ Request, Response, Body, Uri };
use hyper::service::Service;
use hyper::client::{ Client, HttpConnector };
use hyper_rustls::HttpsConnector;


#[derive(Clone)]
pub struct Forward {
    pub tls: Arc<HttpsConnector<HttpConnector>>
}

impl Service for Forward {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response<Self::ResBody>, Error=Self::Error> + 'static + Send>;

    fn call(&mut self, mut req: Request<Self::ReqBody>) -> Self::Future {
        let tls = self.tls.as_ref().clone();

        let builder = Client::builder();

        // XXX force https
        let mut parts = req.uri().clone().into_parts();
        parts.scheme = Some(Scheme::HTTPS);
        if parts.path_and_query.is_none() {
            parts.path_and_query = Some(PathAndQuery::from_static("/"));
        }
        if let Ok(uri) = Uri::from_parts(parts) {
            *req.uri_mut() = uri;
        }

        let headers = req.headers_mut();

        headers.remove("proxy-authorization");

        for key in headers.keys()
            .filter(|key| key.as_str().starts_with("proxy-"))
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
        {
            if let Some(val) = headers.remove(&key) {
                let key = key.as_str().trim_start_matches("proxy-");
                if let Ok(key) = HeaderName::from_bytes(key.as_bytes()) {
                    headers.insert(key, val);
                }
            }
        }

        // FIXME

        eprintln!("{:#?}", req);

        Box::new(builder.build(tls).request(req)
            .map(|resp| {
                eprintln!("{:#?}", resp);
                resp
            })
        )
    }
}
