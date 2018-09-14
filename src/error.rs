use std::borrow::Cow;
use failure::Fail;


#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Parse Error: {:?}", _0)]
    Parse(Cow<'static, str>),

    #[fail(display = "Incomplete: {:?}", _0)]
    Incomplete(usize),

    #[fail(display = "Not a Handshake")]
    NoHandshake,
}
