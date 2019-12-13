use std::convert::TryFrom;
use std::borrow::Cow;
use snafu::{ Snafu, ResultExt };
use rcgen::RcgenError;
use psl::{ Psl, List };
use cache_2q::Cache;


pub struct Entry {
    entry: rcgen::Certificate
}

pub struct CertStore {
    pub entry: Entry,
    cache: Cache<String, rustls::Certificate>
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("rcgen error: {}", source))]
    Rcgen { source: RcgenError },

    #[snafu(display("load certs failed"))]
    LoadCerts,

    #[snafu(display("rustls error: {}", source))]
    Rustls { source: rustls::TLSError }
}

impl CertStore {
    pub fn get(&mut self, name: &str) -> Result<rustls::ServerConfig, Error> {
        let CertStore { entry, cache } = self;

        let name = if let Some(suffix) = List.suffix(name) {
            let end = name.len() - suffix.to_str().len();
            let pos = name[..end].find('.').unwrap_or(end);
            let mut name2 = String::new();
            if !name[..end].is_empty() {
                name2.push('*');
            }
            name2.push_str(&name[pos..]);
            Cow::Owned(name2)
        } else {
            Cow::Borrowed(name)
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
        config.set_single_cert(vec![cert], key).context(Rustls)?;
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
        let kp = rcgen::KeyPair::from_pem(key_input).context(Rcgen)?;
        let params = rcgen::CertificateParams::from_ca_cert_pem(cert_input, kp).context(Rcgen)?;
        let entry = rcgen::Certificate::from_params(params).context(Rcgen)?;
        Ok(Entry { entry })
    }

    pub fn make(&self, cn: &str) -> Result<rustls::Certificate, Error> {
        let Entry { entry } = self;

        let kp = entry.serialize_private_key_der();
        let kp = rcgen::KeyPair::try_from(&*kp).context(Rcgen)?;

        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(rcgen::SanType::DnsName(cn.into()));
        params.serial_number = Some(rand::random());
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "MITM CA");
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.key_pair = Some(kp);

        // TODO
        // not_before
        // not_after

        let der = rcgen::Certificate::from_params(params).context(Rcgen)?
            .serialize_der_with_signer(entry).context(Rcgen)?;

        Ok(rustls::Certificate(der))
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
