use http::uri::{ Scheme, PathAndQuery };
use http::header::HeaderName;
use hyper::{ Request, Uri };
use hyper::service::Service;
use hyper::client::Client;
use hyper_tls::HttpsConnector;
use crate::proxy::Proxy;


pub fn call(proxy: &mut Proxy, mut req: Request<<Proxy as Service>::ReqBody>)
    -> <Proxy as Service>::Future
{
    let http = proxy.http.clone();
    let tls = proxy.tls.clone();
    let https = HttpsConnector::from((http, tls));

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

    Box::new(builder.build(https).request(req))
}
