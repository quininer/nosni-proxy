use std::fs;
use std::io::{ self, BufRead, Write };
use argh::FromArgs;
use rand::{ TryRngCore, rngs::OsRng };


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

        let input = readline!("subject alt names> ");
        let mut list = Vec::new();
        for san in input.split(',') {
            let san = san.parse()?;
            list.push(rcgen::SanType::DnsName(san));
        }
        let on = readline!("organization name> ").to_owned();
        let cn = readline!("common name> ").to_owned();

        let mut params = rcgen::CertificateParams::default();
        params.serial_number = Some(rng.try_next_u64().unwrap().into());
        params.subject_alt_names = list;
        params.distinguished_name.push(rcgen::DnType::OrganizationName, on);
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let kp = rcgen::KeyPair::generate()?;
        let ca_cert = params.self_signed(&kp)?;

        let cert = ca_cert.pem();
        let key = kp.serialize_pem();

        fs::write(format!("{}-ca-cert.pem", name), cert.as_bytes())?;
        fs::write(format!("{}-ca.pem", name), key.as_bytes())?;

        Ok(())
    }
}
