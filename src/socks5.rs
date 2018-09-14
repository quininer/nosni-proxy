use std::io;
use std::net::{ SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr };
use byteorder::{ ByteOrder, NetworkEndian };
use tokio::prelude::*;
use tokio_io::io as aio;
use tokio::net::TcpStream;
use rustls::internal::msgs::codec::Codec;
use crate::error::Error;
use crate::filter::filter_sni;


pub type ReadTcp = aio::ReadHalf<TcpStream>;
pub type WriteTcp = aio::WriteHalf<TcpStream>;

pub struct Connection {
    socket: TcpStream,
    remote: TcpStream,
}

macro_rules! try_ready {
    ( $e:expr ) => (match $e {
        Ok(tokio::prelude::Async::Ready(t)) => t,
        Ok(tokio::prelude::Async::NotReady) => return Ok(tokio::prelude::Async::NotReady),
        Err(e) => return Err(From::from(e)),
    })
}

macro_rules! err {
    ( os $number:expr ) => {
        std::io::Error::from_raw_os_error($number)
    };
    ( $kind:ident ) => {
        std::io::Error::from(
            std::io::ErrorKind::$kind
        )
    };
    ( $kind:ident, $err:expr ) => {
        std::io::Error::new(
            std::io::ErrorKind::$kind,
            $err
        )
    };
    ( $kind:ident, $fmt:expr, $( $args:tt )+ ) => {
        err!($kind, format!($fmt, $($args)+))
    }
}

impl Connection {
    pub fn new(socket: TcpStream, remote: TcpStream) -> Self {
        Connection { socket, remote }
    }

    pub fn handshake(socket: TcpStream) -> impl Future<Item=Connection, Error=io::Error> {
        // read version and nmethods
        aio::read_exact(socket, [0; 2])
            .and_then(|(socket, buf)| if buf[0] == v5::VERSION {
                Ok((socket, buf[1]))
            } else {
                Err(err!(Other, "unsupported version"))
            })
            // read methods
            .and_then(|(socket, n)| aio::read_exact(socket, vec![0u8; n as usize]))
            .and_then(|(socket, v)| if v.contains(&v5::METH_NO_AUTH) {
                Ok(socket)
            } else {
                Err(err!(Other, "no supported method given"))
            })
            // write version and auth method
            .and_then(|socket| aio::write_all(socket, [v5::VERSION, v5::METH_NO_AUTH]))

            // read version and command
            .and_then(|(socket, _)| aio::read_exact(socket, [0; 2]))
            .and_then(|(socket, buf)| match buf {
                [v5::VERSION, v5::CMD_CONNECT] => Ok(socket),
                _ => Err(err!(Other, "unsupported version or command"))
            })
            // read addr
            .and_then(|socket| aio::read_exact(socket, [0; 2]))
            .and_then(|(socket, buf)| match buf[1] {
                v5::ATYP_IPV4 => mybox(aio::read_exact(socket, [0; 4])
                    .map(|(socket, buf)| (socket, IpAddr::V4(Ipv4Addr::from(buf))))),
                v5::ATYP_IPV6 => mybox(aio::read_exact(socket, [0; 16])
                    .map(|(socket, buf)| (socket, IpAddr::V6(Ipv6Addr::from(buf))))),
                // TODO trust dns
                v5::ATYP_DOMAIN => mybox(aio::read_exact(socket, [0])
                    .and_then(|(socket, len)| aio::read_exact(socket, vec![0; len[0] as usize]))
                    .map(|(socket, _)| (socket, IpAddr::V4(Ipv4Addr::from([151, 101, 41, 140]))))),
                n => mybox(future::err(err!(Other, "unknown ATYP received: {}", n)))
            })
            // write response
            .and_then(|(socket, host)| aio::read_exact(socket, [0; 2])
                .and_then(move |(socket, buf)| {
                    let addr = SocketAddr::new(host, NetworkEndian::read_u16(&buf));
                    TcpStream::connect(&addr)
                        .then(move |remote| {
                            let mut resp = [0; 32];
                            resp[0] = v5::VERSION;
                            resp[1] = match remote {
                                Ok(_) => 0,
                                Err(ref e) if e.kind() == io::ErrorKind::NotConnected => 3,
                                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => 6,
                                Err(_) => 1,
                            };
                            resp[2] = 0;
                            let addr = match remote.as_ref().map(|r| r.local_addr()) {
                                Ok(Ok(addr)) => addr,
                                Ok(Err(_)) | Err(_) => addr,
                            };
                            let pos = match addr {
                                SocketAddr::V4(ref a) => {
                                    resp[3] = v5::ATYP_IPV4;
                                    resp[4..][..4].copy_from_slice(&a.ip().octets()[..]);
                                    8
                                }
                                SocketAddr::V6(ref a) => {
                                    resp[3] = v5::ATYP_IPV6;
                                    resp[4..][..16].copy_from_slice(&a.ip().octets()[..]);
                                    20
                                }
                            };
                            NetworkEndian::write_u16(&mut resp[pos..][..2], addr.port());

                            let mut w = aio::Window::new(resp);
                            w.set_end(pos + 2);
                            aio::write_all(socket, w).and_then(|(socket, _)|
                                remote.map(|remote| Connection::new(socket, remote))
                            )
                        })
                })
            )
    }

    pub fn tunnel(self, buf_size: usize) -> (Tunnel<ReadTcp, WriteTcp>, Tunnel<ReadTcp, WriteTcp>) {
        let (socket_reader, socket_writer) = self.socket.split();
        let (remote_reader, remote_writer) = self.remote.split();

        (
            Tunnel::new(socket_reader, remote_writer, buf_size),
            Tunnel::new(remote_reader, socket_writer, buf_size)
        )
    }
}

pub struct Tunnel<R, W> {
    reader: R,
    writer: W,
    buf: Box<[u8]>,
    filtered: bool,
    eof: bool,
    pos: usize,
    end: usize,
    amt: u64
}

impl<R, W> Tunnel<R, W> {
    pub fn new(reader: R, writer: W, buf_size: usize) -> Tunnel<R, W> {
        Tunnel {
            reader, writer,
            buf: vec![0; buf_size].into_boxed_slice(),
            filtered: false,
            eof: false,
            pos: 0,
            end: 0,
            amt: 0
        }
    }
}

impl<R, W> Future for Tunnel<R, W>
where
    R: AsyncRead,
    W: AsyncWrite
{
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if self.pos == self.end && !self.eof {
                self.pos = 0;
                self.end = 0;
            }

            if !self.eof  {
                let n = try_ready!(self.reader.poll_read(&mut self.buf[self.end..]));
                if n == 0 {
                    self.eof = true;
                } else {
                    self.end += n;
                }
            }

            if !self.filtered {
                match filter_sni(&self.buf[self.pos..self.end]) {
                    Ok((len, packet)) => {
                        eprintln!("{:?}", (len, &packet));

                        let remaining = self.buf[self.pos..self.end][len..].to_vec();
                        let buf2 = packet.get_encoding();

                        self.buf[self.pos..][..buf2.len()].copy_from_slice(&buf2);
                        self.buf[self.pos..][buf2.len()..][..remaining.len()].copy_from_slice(&remaining);
                        self.end = self.pos + buf2.len() + remaining.len();

                        self.filtered = true;
                    },
                    Err(Error::Parse(_)) | Err(Error::NoHandshake) => {
                        self.filtered = true;
                        continue
                    },
                    Err(Error::Incomplete(_)) => continue,
                }
            }

            while self.pos < self.end {
                let i = try_ready!(self.writer.poll_write(&self.buf[self.pos..self.end]));
                if i == 0 {
                    return Err(err!(WriteZero, "write zero byte into writer"));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                }
            }

            if self.pos == self.end && self.eof {
                try_ready!(self.writer.poll_flush());
                return Ok(self.amt.into());
            }
        }
    }
}

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

fn mybox<F: Future + Send + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error> + Send> {
    Box::new(f)
}
