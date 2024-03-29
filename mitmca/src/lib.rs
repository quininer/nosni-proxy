use std::convert::TryFrom;
use std::borrow::Cow;
use thiserror::Error;
use rcgen::RcgenError;
use time::{ OffsetDateTime, Duration };
use psl::{ Psl, List };
use cache_2q::Cache;


pub struct Entry {
    entry: rcgen::Certificate,
    der: Vec<u8>
}

pub struct CertStore {
    pub entry: Entry,
    cache: Cache<String, rustls::Certificate>
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("rcgen error: {0}")]
    Rcgen(#[from] RcgenError),

    #[error("load certs failed")]
    LoadCerts,

    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error)
}

impl CertStore {
    pub fn get(&mut self, name: &str) -> Result<rustls::ServerConfig, Error> {
        let CertStore { entry, cache } = self;

        let name = take_generic(name);
        let cert = match cache.entry(name.into_owned()) {
            cache_2q::Entry::Occupied(e) => e.get().clone(),
            cache_2q::Entry::Vacant(e) => {
                let cert = entry.make(e.key())?;
                e.insert(cert).clone()
            }
        };

        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], rustls::PrivateKey(entry.der.clone()))?;
        Ok(config)
    }
}

impl From<Entry> for CertStore {
    fn from(entry: Entry) -> CertStore {
        CertStore { entry, cache: Cache::new(32) }
    }
}

impl Entry {
    pub fn from_pem(cert_input: &str, key_input: &str) -> Result<Entry, Error> {
        let kp = rcgen::KeyPair::from_pem(key_input)?;
        let params = rcgen::CertificateParams::from_ca_cert_pem(cert_input, kp)?;
        let entry = rcgen::Certificate::from_params(params)?;
        let der = entry.serialize_private_key_der();
        Ok(Entry { entry, der })
    }

    pub fn make(&self, cn: &str) -> Result<rustls::Certificate, Error> {
        let Entry { entry, der } = self;

        thread_local!{
            static TODAY: OffsetDateTime = OffsetDateTime::now_utc();
        }

        let kp = rcgen::KeyPair::try_from(der.as_slice())?;

        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(rcgen::SanType::DnsName(cn.into()));
        params.serial_number = Some(rand::random::<u64>().into());
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "MITM CA");
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.key_pair = Some(kp);
        TODAY.with(|today| {
            params.not_before = *today - Duration::days(1);
            params.not_after = *today + Duration::weeks(1);
        });

        let der = rcgen::Certificate::from_params(params)?
            .serialize_der_with_signer(entry)?;

        Ok(rustls::Certificate(der))
    }
}

fn take_generic(name: &str) -> Cow<'_, str> {
    static LIST: List = List;

    if let Some(suffix) = LIST.suffix(name.as_bytes()) {
        let end = name.len() - suffix.as_bytes().len();
        let pos = name[..end]
            .trim_end_matches('.')
            .find('.')
            .unwrap_or(0);

        let mut name2 = String::new();
        if !name[..pos].is_empty() {
            name2.push('*');
        }
        name2.push_str(&name[pos..]);
        Cow::Owned(name2)
    } else {
        Cow::Borrowed(name)
    }
}

#[test]
fn test_generic() {
    assert_eq!(take_generic("test"), "test");
    assert_eq!(take_generic("test.com"), "test.com");
    assert_eq!(take_generic("a.test.com"), "*.test.com");
    assert_eq!(take_generic("a.b.test.com"), "*.b.test.com");
}

#[test]
fn test_mitmca() {
    use std::time::SystemTime;

    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names.push(rcgen::SanType::DnsName("localhost".into()));
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "MITM CA");
    params.distinguished_name.push(rcgen::DnType::CommonName, "MITM CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = rcgen::Certificate::from_params(params).unwrap();
    let der = ca_cert.serialize_private_key_der();

    let entry = Entry { entry: ca_cert, der };
    let ca_cert_der = entry.entry.serialize_der().unwrap();
    let trust_anchor_list = &[webpki::TrustAnchor::try_from_cert_der(&ca_cert_der).unwrap()];
    let trust_anchors = webpki::TlsServerTrustAnchors(trust_anchor_list);
    let rustls::Certificate(cert) = entry.make("localhost.dev").unwrap();

    let end_entity_cert = webpki::EndEntityCert::try_from(cert.as_slice()).unwrap();
    let time = webpki::Time::try_from(SystemTime::now()).unwrap();
    end_entity_cert.verify_is_valid_tls_server_cert(
            &[&webpki::ECDSA_P256_SHA256],
            &trust_anchors,
            &[&ca_cert_der],
            time,
    ).expect("valid TLS server cert");
}
