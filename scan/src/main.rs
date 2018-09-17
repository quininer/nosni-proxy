use std::{ env, fs };
use std::io::{ self, BufRead };
use futures::future::IntoFuture;
use hyper::{ client, Client, Body };
use hyper::rt::{ self, Future };
use hyper_rustls::HttpsConnector;


fn main() -> io::Result<()> {
    let mut iter = env::args().skip(1);

    let path = iter.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "usage: nosni-scan <file>"))?;
    let list = fs::File::open(path)?;

    let mut http = client::HttpConnector::new(4);
    http.enforce_http(false);
    let mut tls = rustls::ClientConfig::new();
    tls.enable_sni = false;
    tls.root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let https = HttpsConnector::from((http, tls));

    let done = rt::lazy(move || {
        for line in io::BufReader::new(list).lines() {
            let client = Client::builder()
                .keep_alive(false)
                .build::<_, Body>(https.clone());

            let done = line.into_future()
                .and_then(|line| line.parse::<hyper::Uri>()
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                )
                .and_then(move |uri| client.get(uri.clone())
                    .map(move |resp| (resp, uri))
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                )
                .map(|(resp, uri)| if resp.status().is_success() {
                    println!("{}", uri);
                })
                .map_err(drop);

            rt::spawn(done);
        }

        Ok(())
    });

    rt::run(done);
    Ok(())
}
