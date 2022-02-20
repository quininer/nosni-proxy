use std::path::PathBuf;
use std::net::{ SocketAddr, IpAddr };
use std::collections::HashMap;
use serde::Deserialize;


#[derive(Deserialize)]
pub struct Config {
    pub bind: SocketAddr,
    pub alpn: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub doh: Option<Doh>,
    pub mapping: HashMap<String, Rule>,
}

#[derive(Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub addr: Option<StrOrList<IpAddr>>
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
