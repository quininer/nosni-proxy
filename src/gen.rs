use std::fs;
use argh::FromArgs;
use rustyline::Editor;
use rand::{ Rng, rngs::OsRng };


/// local CA certs generator
#[derive(FromArgs)]
#[argh(subcommand, name = "gen")]
pub struct Options {
    /// crets file prefix
    #[argh(positional)]
    name: String
}

impl Options {
    pub fn exec(self) -> anyhow::Result<()> {
        let mut rng = OsRng;
        let name = self.name.as_str();

        let mut rl = Editor::<()>::new();
        let san = rl.readline("subject alt names> ")?
            .split(',')
            .map(str::to_string)
            .map(rcgen::SanType::DnsName)
            .collect::<Vec<_>>();
        let on = rl.readline("organization name> ")?;
        let cn = rl.readline("common name> ")?;

        let mut params = rcgen::CertificateParams::default();
        params.serial_number = Some(rng.gen());
        params.subject_alt_names = san;
        params.distinguished_name.push(rcgen::DnType::OrganizationName, on);
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = rcgen::Certificate::from_params(params)?;

        let cert = ca_cert.serialize_pem()?;
        let key = ca_cert.serialize_private_key_pem();

        fs::write(format!("{}-ca-cert.pem", name), cert.as_bytes())?;
        fs::write(format!("{}-ca.pem", name), key.as_bytes())?;

        Ok(())
    }
}
