use std::convert::TryFrom;
use std::borrow::Cow;
use failure::Fail;
use rcgen::RcgenError;
use publicsuffix::{ List, errors::ErrorKind };
use cache_2q::Cache;
use lazy_static::lazy_static;
use if_chain::if_chain;


pub struct Entry {
    entry: rcgen::Certificate
}

pub struct CertStore {
    pub entry: Entry,
    cache: Cache<String, rustls::Certificate>
}

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "rcgen error: {}", _0)]
    Rcgen(RcgenError),

    #[fail(display = "publicsuffix parse error: {}", _0)]
    PubSuffix(ErrorKind),

    #[fail(display = "load certs failed",)]
    LoadCerts,

    #[fail(display = "rustls error: {}", _0)]
    Rustls(rustls::TLSError)
}

impl CertStore {
    pub fn get(&mut self, name: &str) -> Result<rustls::ServerConfig, Error> {
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
                let end = name.len() - root.len();
                let pos = name[..end].find('.').unwrap_or(end);
                let mut name2 = String::new();
                if !name[..end].is_empty() {
                    name2.push('*');
                }
                name2.push_str(&name[pos..]);
                Cow::Owned(name2)
            } else {
                Cow::Borrowed(name)
            }
        };

        let cert = match cache.entry(name.into_owned()) {
            cache_2q::Entry::Occupied(e) => e.get().clone(),
            cache_2q::Entry::Vacant(e) => {
                let cert = entry.make(e.key())?;
                e.insert(cert).clone()
            }
        };

        let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        let key = rustls::PrivateKey(self.entry.entry.serialize_private_key_der());
        config.set_single_cert(vec![cert], key)?;
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
        Ok(Entry { entry })
    }

    pub fn make(&self, cn: &str) -> Result<rustls::Certificate, Error> {
        let Entry { entry } = self;

        let kp = entry.serialize_private_key_der();
        let kp = rcgen::KeyPair::try_from(&*kp)?;

        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(cn.into());
        params.serial_number = Some(rand::random());
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "MITM CA");
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.key_pair = Some(kp);

        // TODO
        // not_before
        // not_after

        let der = rcgen::Certificate::from_params(params)?
            .serialize_der_with_signer(entry)?;

        Ok(rustls::Certificate(der))
    }
}

impl From<RcgenError> for Error {
    fn from(err: RcgenError) -> Error {
        Error::Rcgen(err)
    }
}

impl From<rustls::TLSError> for Error {
    fn from(err: rustls::TLSError) -> Error {
        Error::Rustls(err)
    }
}

impl From<publicsuffix::Error> for Error {
    fn from(err: publicsuffix::Error) -> Error {
        Error::PubSuffix(err.0)
    }
}

#[test]
fn test_mitmca() {
    use webpki::{ self, EndEntityCert, Time, TLSServerTrustAnchors };
    use webpki::trust_anchor_util::cert_der_as_trust_anchor;
    use untrusted::Input;

    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names.push("localhost".into());
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "MITM CA");
    params.distinguished_name.push(rcgen::DnType::CommonName, "MITM CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = rcgen::Certificate::from_params(params).unwrap();

    let entry = Entry { entry: ca_cert };
    let ca_cert_der = entry.entry.serialize_der().unwrap();
    let trust_anchor_list = &[cert_der_as_trust_anchor(Input::from(&ca_cert_der)).unwrap()];
    let trust_anchors = TLSServerTrustAnchors(trust_anchor_list);
    let rustls::Certificate(cert) = entry.make("localhost.dev").unwrap();

    let end_entity_cert = EndEntityCert::from(Input::from(&cert)).unwrap();
    let time = Time::from_seconds_since_unix_epoch(0x40_00_00_00);
    end_entity_cert.verify_is_valid_tls_server_cert(
            &[&webpki::ECDSA_P256_SHA256],
            &trust_anchors,
            &[Input::from(&ca_cert_der)],
            time,
    ).expect("valid TLS server cert");
}
