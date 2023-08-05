use std::fs;
use std::io::{ self, BufRead, Write };
use argh::FromArgs;
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

        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        let mut line = String::new();

        macro_rules! readline {
            ( $prompt:expr ) => {{
                line.clear();
                write!(&mut stdout, $prompt)?;
                stdout.flush()?;
                stdin.read_line(&mut line)?;
                line.as_str()
            }}
        }

        let san = readline!("subject alt names> ")
            .split(',')
            .map(str::to_string)
            .map(rcgen::SanType::DnsName)
            .collect::<Vec<_>>();
        let on = readline!("organization name> ").to_owned();
        let cn = readline!("common name> ").to_owned();

        let mut params = rcgen::CertificateParams::default();
        params.serial_number = Some(rng.gen::<u64>().into());
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
