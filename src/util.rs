use std::{ io, mem };
use std::pin::Pin;
use std::marker::Unpin;
use std::future::Future;
use std::time::Duration;
use std::task::{ ready, Context, Poll };
use tokio::time::{ sleep, Sleep, Instant };
use tokio::io::{ AsyncRead, AsyncWrite, ReadBuf };
use tokio_rustls::rustls::compress::{ CertDecompressor, DecompressionFailed };
use tokio_rustls::rustls::CertificateCompressionAlgorithm;


#[derive(Debug)]
pub struct ZlibDecompressor;

impl CertDecompressor for ZlibDecompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), DecompressionFailed> {
        fdeflate::Decompressor::new().read(input, output, 0, true)
            .ok()
            .filter(|(_consumed, produced)| *produced == output.len())
            .map(drop)
            .ok_or(DecompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
pub struct ZstdDecompressor;

impl CertDecompressor for ZstdDecompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), DecompressionFailed> {
        use std::io::Read;

        let mut decoder = ruzstd::streaming_decoder::StreamingDecoder::new(input)
            .map_err(|_| DecompressionFailed)?;
        decoder.read_exact(output).map_err(|_| DecompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}

pub type FragmentFn = Box<dyn Fn(u16) -> (u16, Duration) + Send + Sync>;

pub struct FragmentStream<Stream> {
    stream: Stream,
    fragment: Option<FragmentFn>,
    state: State
}

struct Buffer<B> {
    buf: B,
    pos: usize
}

enum State {
    Start(Buffer<[u8; 5]>),
    ReadHello {
        header: [u8; 5],
        buf: Buffer<Box<[u8]>>
    },
    WriteHello {
        sleep: Pin<Box<Sleep>>,
        need_flush: bool,
        header: Buffer<[u8; 5]>,
        buf: Buffer<Box<[u8]>>,
        chunk_len: u16
    },
    Fallback(Buffer<[u8; 5]>),
    Done
}

impl<B> Buffer<B> {
    const fn new(buf: B) -> Self {
        Buffer { buf, pos: 0 }
    }

    fn get_ref(&self) -> &B {
        &self.buf
    }

    fn get_mut(&mut self) -> &mut B {
        &mut self.buf
    }

    fn reset(&mut self) {
        self.pos = 0;
    }
}

impl<B: AsRef<[u8]>> Buffer<B> {
    fn unread_ref(&self) -> &[u8] {
        &self.buf.as_ref()[self.pos..]
    }

    fn remaining(&self) -> usize {
        self.buf.as_ref().len() - self.pos
    }
}

impl<B: AsMut<[u8]>> Buffer<B> {
    fn unfill_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[self.pos..]
    }

    fn advance(&mut self, num: usize) {
        self.pos += num;
    }
}

impl<Stream> FragmentStream<Stream> {
    pub fn new(stream: Stream) -> Self {
        FragmentStream {
            stream,
            fragment: None,
            state: State::Done
        }
    }

    pub fn set_fragment(mut self, fragment_fn: Option<FragmentFn>) -> Self {
        self.fragment = fragment_fn;
        self.state = if self.fragment.is_some() {
            State::Start(Buffer::new([0; 5]))
        } else {
            State::Done
        };
        self
    }
}

impl<Stream: AsyncRead + Unpin> AsyncRead for FragmentStream<Stream> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<Stream: AsyncWrite + Unpin> AsyncWrite for FragmentStream<Stream> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        const HANDSHAKE_TYPE: u8 = 0x16;
        const TLS: u16 = 0x0300;

        match &mut this.state {
            State::Start(buf) => {
                let len = std::cmp::min(buf.remaining(), input.len());
                buf.unfill_mut()[..len].copy_from_slice(&input[..len]);
                buf.advance(len);

                if buf.remaining() == 0 {
                    let buf = buf.get_ref();
                    let ty = buf[0];
                    let ver = u16::from_be_bytes([buf[1], buf[2]]);
                    let len = u16::from_be_bytes([buf[3], buf[4]]);

                    if ty == HANDSHAKE_TYPE && ver & 0xff00 == TLS {
                        let boxbuf = vec![0; len.into()].into_boxed_slice();
                        this.state = State::ReadHello {
                            header: *buf,
                            buf: Buffer::new(boxbuf)
                        };
                    } else {
                        this.state = State::Fallback(Buffer::new(*buf));
                    }
                }

                Poll::Ready(Ok(len))
            },
            State::ReadHello { header, buf } => {
                let len = std::cmp::min(buf.remaining(), input.len());
                buf.unfill_mut()[..len].copy_from_slice(&input[..len]);
                buf.advance(len);

                if buf.remaining() == 0 {
                    buf.reset();

                    let buf_len = buf.remaining().try_into().map_err(|_| bad_length())?;
                    let fragment = this.fragment.as_ref().unwrap();
                    let (len, dur) = fragment(buf_len);
                    let lenbuf = len.to_be_bytes();
                    let mut header = *header;
                    header[3] = lenbuf[0];
                    header[4] = lenbuf[1];

                    this.state = State::WriteHello {
                        need_flush: false,
                        sleep: Box::pin(sleep(dur)),
                        header: Buffer::new(header),
                        buf: Buffer::new(mem::take(buf.get_mut())),
                        chunk_len: len
                    };
                }

                cx.waker().wake_by_ref();

                Poll::Pending
            },
            State::WriteHello { sleep, need_flush, header, buf, chunk_len } => {
                if *need_flush {
                    ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
                    *need_flush = false;

                    let buf_len = buf.remaining().try_into().map_err(|_| bad_length())?;
                    let fragment = this.fragment.as_ref().unwrap();
                    let (len, dur) = fragment(buf_len);
                    let lenbuf = len.to_be_bytes();
                    header.reset();
                    let header = header.unfill_mut();
                    header[3] = lenbuf[0];
                    header[4] = lenbuf[1];
                    *chunk_len = len;

                    sleep.as_mut().reset(Instant::now() + dur);
                }

                ready!(sleep.as_mut().poll(cx));

                while header.remaining() > 0 {
                    let n = ready!(Pin::new(&mut this.stream).poll_write(cx, header.unread_ref()))?;
                    header.advance(n);
                }

                let len = std::cmp::min(buf.remaining(), (*chunk_len).into());
                let n = ready!(Pin::new(&mut this.stream).poll_write(cx, &buf.unread_ref()[..len]))?;
                buf.advance(n);
                *chunk_len -= u16::try_from(n).map_err(|_| bad_length())?;

                if buf.remaining() == 0 {
                    this.state = State::Done;
                } else {
                    *need_flush = true;
                }

                Poll::Ready(Ok(n))
            },
            State::Fallback(buf) => {
                let n = ready!(Pin::new(&mut this.stream).poll_write(cx, &buf.unread_ref()))?;
                buf.advance(n);

                if buf.remaining() == 0 {
                    this.state = State::Done;
                }

                Poll::Ready(Ok(n))
            }
            State::Done => Pin::new(&mut this.stream).poll_write(cx, input)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.fragment.is_none() || matches!(this.state, State::Done) {
            Pin::new(&mut this.stream).poll_write_vectored(cx, bufs)
        } else {
            let mut n = 0;
            for buf in bufs {
                n += ready!(Pin::new(&mut *this).poll_write(cx, buf))?;
            }
            Poll::Ready(Ok(n))
        }
    }

    fn is_write_vectored(&self) -> bool {
        matches!(self.state, State::Done)
    }
}

pub fn bad_length() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "bad length")
}
