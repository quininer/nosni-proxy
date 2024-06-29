use std::convert::TryFrom;
use std::borrow::Cow;
use thiserror::Error;
use time::{ OffsetDateTime, Duration };
use psl::{ Psl, List };
use cache_2q::Cache;


pub struct Entry {
    kp: rcgen::KeyPair,
    params: rcgen::CertificateParams,
    skder: rustls::pki_types::PrivateKeyDer<'static>
}

pub struct CertStore {
    pub entry: Entry,
    cache: Cache<String, rustls::pki_types::CertificateDer<'static>>
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("pem parse error: {0}")]
    Pem(#[from] pem::PemError),

    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("load certs failed")]
    LoadCerts(&'static str),

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
            .with_no_client_auth()
            .with_single_cert(vec![cert], entry.skder.clone_key())?;
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
        let key_input = pem::parse(key_input)?;
        let skder = <rustls::pki_types::PrivateKeyDer<'_>>::try_from(key_input.contents())
            .map_err(Error::LoadCerts)?
            .clone_key();
        let kp = rcgen::KeyPair::try_from(&skder)?;
        let params = rcgen::CertificateParams::from_ca_cert_pem(cert_input)?;
        Ok(Entry { kp, params, skder })
    }

    pub fn make(&self, cn: &str) -> Result<rustls::pki_types::CertificateDer<'static>, Error> {
        thread_local!{
            static TODAY: OffsetDateTime = OffsetDateTime::now_utc();
        }

        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(rcgen::SanType::DnsName(cn.parse()?));
        params.serial_number = Some(rand::random::<u64>().into());
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "MITM CA");
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        TODAY.with(|today| {
            params.not_before = *today - Duration::days(1);
            params.not_after = *today + Duration::weeks(1);
        });

        let cert = params.signed_by2(&self.kp, &self.params, &self.kp)?;

        Ok(cert.into())
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
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names.push(rcgen::SanType::DnsName("localhost".parse().unwrap()));
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "MITM CA");
    params.distinguished_name.push(rcgen::DnType::CommonName, "MITM CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = params.clone().self_signed(&kp).unwrap();
    let skder = rustls::pki_types::PrivateKeyDer::try_from(kp.serialized_der()).unwrap();
    let skder = skder.clone_key();

    let entry = Entry { kp, params, skder };

    let ca_cert_der = ca_cert.der();
    let trust_anchor = webpki::anchor_from_trusted_cert(ca_cert_der).unwrap();
    let cert = entry.make("localhost.dev").unwrap();

    let end_entity_cert = webpki::EndEntityCert::try_from(&cert).unwrap();
    end_entity_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[trust_anchor],
        &[],
        rustls::pki_types::UnixTime::now(),
        webpki::KeyUsage::server_auth(),
        None,
        None
    ).unwrap();
}
