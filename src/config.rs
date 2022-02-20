use std::path::PathBuf;
use std::net::SocketAddr;
use std::collections::HashMap;
use serde::Deserialize;


#[derive(Deserialize)]
pub struct Config {
    pub bind: SocketAddr,
    pub alpn: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub doh: Option<Doh>,
    pub mapping: HashMap<String, String>,
    pub hosts: Option<HashMap<String, String>>
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
