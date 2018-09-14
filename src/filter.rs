use std::borrow::Cow;
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload;
use rustls::internal::msgs::enums::HandshakeType;
use rustls::internal::msgs::handshake::HandshakePayload;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::codec::Codec;
use crate::error::Error;


const HEADER_SIZE: usize = 1 + 2 + 2;

pub fn filter_sni(input: &[u8]) -> Result<(usize, Message), Error> {
    let want = Message::check_header(input)
        .ok_or_else(|| Error::Parse(Cow::Borrowed("Bad Message")))?;

    if want + HEADER_SIZE > input.len() {
        Err(Error::Incomplete(want))
    } else {
        let mut msg = Message::read_bytes(input)
            .ok_or_else(|| Error::Parse(Cow::Borrowed("Bad Parse")))?;
        msg.decode_payload();

        if !msg.is_handshake_type(HandshakeType::ClientHello) {
            return Err(Error::NoHandshake);
        }

        if let MessagePayload::Handshake(ref mut payload) = msg.payload {
            if let HandshakePayload::ClientHello(ref mut payload) = payload.payload {
                if let Some((i, _)) = payload.extensions.iter()
                    .enumerate()
                    .find(|(_, ext)| ext.get_type() == ExtensionType::ServerName)
                {
                    payload.extensions.remove(i);
                }
            }
        }

        Ok((want + HEADER_SIZE, msg))
    }
}
