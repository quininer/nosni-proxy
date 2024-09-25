use std::net::{ SocketAddr, IpAddr };
use std::marker::Unpin;

use tokio::io::{
    AsyncRead, AsyncWrite,
    AsyncReadExt, AsyncWriteExt
};


#[derive(Debug)]
pub enum Address {
    Addr(SocketAddr),
    Domain(String, u16)
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

pub async fn handshake<S>(stream: &mut S)
    -> anyhow::Result<Address>
where
    S: AsyncRead + AsyncWrite + Unpin
{
    // read version
    {
        let version = stream.read_u8().await?;
        if version != v5::VERSION {
            anyhow::bail!("unimplemented version: {}", version);
        }
    }

    // read auth method
    {
        let len = stream.read_u8().await?;
        let len: usize = len.into();
        let mut buf = [0; 256];
        stream.read_exact(&mut buf[..len]).await?;
        if !buf[..len].contains(&v5::METH_NO_AUTH) {
            anyhow::bail!("no supported auth method given");
        }
    }

    // write version and auth method
    stream.write_all(&[v5::VERSION, v5::METH_NO_AUTH]).await?;
    stream.flush().await?;

    // read version
    {
        let version = stream.read_u8().await?;
        if version != v5::VERSION {
            anyhow::bail!("didn't confirm with v5 version: {}", version);
        }
    }

    // read cmd
    {
        let cmd = stream.read_u8().await?;
        if cmd != v5::CMD_CONNECT {
            anyhow::bail!("unsupported command: {}", cmd);
        }
    }

    // read addr
    let addr = {
        let _ = stream.read_u8().await?; // reserved
        let atyp = stream.read_u8().await?;
        match atyp {
            v5::ATYP_IPV4 => {
                let mut buf = [0; 4];
                stream.read_exact(&mut buf).await?;
                let port = stream.read_u16().await?;
                Address::Addr(SocketAddr::from((buf, port)))
            },
            v5::ATYP_IPV6 => {
                let mut buf = [0; 16];
                stream.read_exact(&mut buf).await?;
                let port = stream.read_u16().await?;
                Address::Addr(SocketAddr::from((buf, port)))
            },
            v5::ATYP_DOMAIN => {
                let len = stream.read_u8().await?;
                let len: usize = len.into();
                let mut buf = vec![0; len];
                stream.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf)?;
                let port = stream.read_u16().await?;

                if let Ok(addr) = domain.parse::<IpAddr>() {
                    Address::Addr(SocketAddr::from((addr, port)))
                } else {
                    Address::Domain(domain, port)
                }
            },
            _ => anyhow::bail!("unknown ATYP received: {}", atyp)
        }
    };

    Ok(addr)
}

pub async fn response<S>(stream: &mut S, reply: u8, addr: SocketAddr)
    -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin
{
    let mut buf = [0; 4];

    buf[0] = v5::VERSION;   // version
    buf[1] = reply;         // reply field
    buf[2] = 0x0;           // reserved

    match addr {
        SocketAddr::V4(addr) => {
            buf[3] = v5::ATYP_IPV4;
            stream.write_all(&buf).await?;
            stream.write_all(&addr.ip().octets()).await?;
            stream.write_all(&addr.port().to_be_bytes()).await?;
        },
        SocketAddr::V6(addr) => {
            buf[3] = v5::ATYP_IPV6;
            stream.write_all(&buf).await?;
            stream.write_all(&addr.ip().octets()).await?;
            stream.write_all(&addr.port().to_be_bytes()).await?;
        }
    }

    stream.flush().await?;

    Ok(())
}
