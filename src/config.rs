use std::path::PathBuf;
use std::net::{ SocketAddr, IpAddr };
use std::collections::HashMap;
use serde::Deserialize;


#[derive(Deserialize)]
pub struct Config {
    pub mitm: Option<Mitm>,
    pub fragment: Option<Fragment>,
    pub doh: Option<Doh>,
    pub mapping: HashMap<String, Rule>,
}

#[derive(Deserialize, Clone)]
pub struct Fragment {
    pub bind: SocketAddr,
    pub size: (u16, u16),
    pub delay: Option<(u64, u64)>,
}

#[derive(Deserialize)]
pub struct Mitm {
    pub bind: SocketAddr,
    pub alpn: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub addr: Option<StrOrList<IpAddr>>,
    #[serde(default, rename = "force-no-sni")]
    pub force_no_sni: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum StrOrList<T> {
    Str(String),
    List(Vec<T>)
}

#[derive(Deserialize)]
pub struct Doh {
    pub addr: SocketAddr,
    pub name: String,

    #[serde(default)]
    pub sni: bool,

    #[cfg_attr(not(feature = "dnssec"), allow(dead_code))]
    #[serde(default)]
    pub dnssec: bool
}
