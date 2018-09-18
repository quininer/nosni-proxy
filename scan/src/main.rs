use std::{ env, fs };
use std::io::{ self, BufRead };
use futures::future::IntoFuture;
use hyper::{ client, Client, Body, Request };
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
            let line2 = line.as_ref().ok().cloned();

            let done = line.into_future()
                .and_then(|line| line.parse::<hyper::Uri>()
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                )
                .and_then(move |uri| {
                    let req = Request::get(&uri)
                        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")
                        .body(Body::empty())
                        .unwrap();
                    client.request(req)
                        .map(move |resp| (resp, uri.clone()))
                        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                })
                .map(|(resp, uri)| if resp.status().is_success() {
                    println!("{}", uri);
                } else {
                    eprintln!("{}: {:?}", uri, resp);
                })
                .map_err(move |err| eprintln!("{:?}: {:?}", line2, err));

            rt::spawn(done);
        }

        Ok(())
    });

    rt::run(done);
    Ok(())
}
