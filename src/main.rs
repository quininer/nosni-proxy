mod error;
mod filter;
mod socks5;

use std::io;
use std::net::SocketAddr;
use tokio::prelude::*;
use tokio::net::TcpListener;
use crate::socks5::Connection;


fn main() -> io::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 1087));
    let listener = TcpListener::bind(&addr)?;

    let done = listener.incoming()
        .for_each(|socket| {
            eprintln!("local: {:?}", socket.local_addr());

            let done = Connection::handshake(socket)
                .and_then(|conn| {
                    eprintln!("handshake done");

                    let (x, y) = conn.tunnel(64 * 1024);
                    x.join(y)
                })
                .map(drop)
                .map_err(|err| eprintln!("{:?}", err));

            tokio::spawn(done);

            Ok(())
        })
        .map_err(|err| eprintln!("{:?}", err));

    tokio::run(done);
    Ok(())
}
