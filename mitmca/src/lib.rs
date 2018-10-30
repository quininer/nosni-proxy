use std::sync::Arc;
use std::borrow::{ Cow, Borrow };
use failure::Fail;
use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::bn::{ BigNum, MsbOption };
use openssl::pkcs12::ParsedPkcs12;
use openssl::ssl::{ SslAcceptorBuilder, SslAcceptor, SslMethod };
use openssl::x509::{ X509, X509NameBuilder };
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
    SubjectAlternativeName, SubjectKeyIdentifier
};
use publicsuffix::{ List, errors::ErrorKind };
use lru_time_cache::LruCache;
use lazy_static::lazy_static;
use if_chain::if_chain;


pub struct Entry(pub ParsedPkcs12);

pub struct CertStore {
    pub entry: Entry,
    cache: LruCache<String, Arc<X509>>
}

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "openssl error: {}", _0)]
    OpenSSL(ErrorStack),

    #[fail(display = "publicsuffix parse error: {}", _0)]
    PubSuffix(ErrorKind)
}

impl CertStore {
    fn get_cert(&mut self, name: &str) -> Result<Arc<X509>, Error> {
        let CertStore { entry, cache } = self;

        lazy_static!{
            static ref LIST: List = {
                const PUB_SUFFIX_LIST: &str = include_str!("../public_suffix_list.dat");

                List::from_str(PUB_SUFFIX_LIST).unwrap()
            };
        }

        let name = if_chain!{
            if let publicsuffix::Host::Domain(domain) = LIST.parse_host(name)?;
            if let Some(root) = domain.root();
            then {
                let mut name2 = name[..name.len() - root.len()].split('.')
                    .filter(|c| !c.is_empty())
                    .fold(String::new(), |mut sum, _| {
                        sum.push_str("*.");
                        sum
                    });
                name2.push_str(root);
                Cow::Owned(name2)
            } else {
                Cow::Borrowed(name)
            }
        };

        if let Some(cert) = cache.get(&*name) {
            // TODO check cert time

            Ok(cert.clone())
        } else {
            let cert = Arc::new(entry.make(&name)?);
            cache.insert(name.into_owned(), cert.clone());
            Ok(cert)
        }
    }

    pub fn get(&mut self, name: &str) -> Result<SslAcceptorBuilder, Error> {
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
        let cert = self.get_cert(name)?;
        builder.set_private_key(self.entry.0.pkey.as_ref())?;
        builder.set_certificate(cert.as_ref())?;
        builder.check_private_key()?;
        Ok(builder)
    }
}

impl From<Entry> for CertStore {
    fn from(entry: Entry) -> CertStore {
        CertStore { entry, cache: LruCache::with_capacity(32) }
    }
}

impl Entry {
    pub fn make(&self, cn: &str) -> Result<X509, ErrorStack> {
        let Entry(ParsedPkcs12 { pkey, cert, .. }) = self;
        let mut cert_builder = X509::builder()?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "CN")?;
        x509_name.append_entry_by_text("ST", "GZ")?;
        x509_name.append_entry_by_text("O", "MITM CA")?;
        x509_name.append_entry_by_text("CN", cn)?;
        let x509_name = x509_name.build();
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(cert.subject_name())?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(32)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().build()?)?;

        cert_builder.append_extension(KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?)?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(cert), None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(cert), None))?;
        cert_builder.append_extension(auth_key_identifier)?;

        let subject_alt_name = SubjectAlternativeName::new()
            .dns(cn)
            .build(&cert_builder.x509v3_context(Some(cert), None))?;
        cert_builder.append_extension(subject_alt_name)?;

        cert_builder.set_pubkey(cert.public_key()?.borrow())?;
        cert_builder.sign(pkey.borrow(), MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok(cert)
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::OpenSSL(err)
    }
}

impl From<publicsuffix::Error> for Error {
    fn from(err: publicsuffix::Error) -> Error {
        Error::PubSuffix(err.0)
    }
}


/*
#[test]
fn test_mitmca() -> Result<(), ErrorStack> {
    use openssl::x509::X509VerifyResult;

    let mut cert_store = CertStore::new("nosni")?;
    let cert = cert_store.get("test.dev")?;

    assert_eq!(
        X509VerifyResult::OK,
        cert_store.ca.1.issued(cert.as_ref().borrow())
    );

    Ok(())
}
*/
