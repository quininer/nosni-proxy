use std::{ io, mem };
use std::pin::Pin;
use std::marker::Unpin;
use std::future::Future;
use std::time::Duration;
use std::num::NonZeroUsize;
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

pub struct FragmentStream<Stream> {
    stream: Stream,
    fragment_size: NonZeroUsize,
    duration: Option<Duration>,
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
    fn fragment(&self, n: NonZeroUsize) -> io::Result<u16> {
        std::cmp::min(self.remaining(), n.get())
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bad hello size"))
    }

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
            fragment_size: NonZeroUsize::new(77).unwrap(),
            duration: Some(Duration::from_millis(100)),
            state: State::Start(Buffer::new([0; 5]))
        }
    }

    pub fn set_fragment_size(&mut self, fragment_size: NonZeroUsize) {
        self.fragment_size = fragment_size;
    }

    pub fn set_time(&mut self, dur: Duration) {
        self.duration = Some(dur);
    }

    pub fn disable(&mut self) {
        self.state = State::Done;
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
                    let len = buf.fragment(this.fragment_size)?.to_be_bytes();
                    let mut header = *header;
                    header[3] = len[0];
                    header[4] = len[1];

                    this.state = State::WriteHello {
                        need_flush: false,
                        sleep: Box::pin(sleep(Duration::from_secs(0))),
                        header: Buffer::new(header),
                        buf: Buffer::new(mem::take(buf.get_mut()))
                    };
                }

                cx.waker().wake_by_ref();

                Poll::Pending
            },
            State::WriteHello { sleep, need_flush, header, buf } => {
                if *need_flush {
                    ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
                    *need_flush = false;

                    let len = buf.fragment(this.fragment_size)?.to_be_bytes();
                    header.reset();
                    let header = header.unfill_mut();
                    header[3] = len[0];
                    header[4] = len[1];
                }

                ready!(sleep.as_mut().poll(cx));

                while header.remaining() > 0 {
                    let n = ready!(Pin::new(&mut this.stream).poll_write(cx, header.unread_ref()))?;
                    dbg!(header.unread_ref(), n);
                    header.advance(n);
                }

                let len = std::cmp::min(buf.remaining(), this.fragment_size.get());
                let n = ready!(Pin::new(&mut this.stream).poll_write(cx, &buf.unread_ref()[..len]))?;
                buf.advance(n);

                if buf.remaining() == 0 {
                    this.state = State::Done;
                } else {
                    if let Some(dur) = this.duration.as_ref() {
                        sleep.as_mut().reset(Instant::now() + *dur);
                    }
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

    /*
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_write_vectored(cx, bufs)
    }
    */

    fn is_write_vectored(&self) -> bool {
        matches!(self.state, State::Done)
    }
}
