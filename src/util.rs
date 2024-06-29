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
