use libc::{ c_int, c_long, c_void };
use libloading::{ Library, Symbol };
use once_cell::sync::Lazy;


type SslCtrlSymbol<'a> = Symbol<
    'a,
    fn(ssl: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long
>;

static OPENSSL: Lazy<Library> = Lazy::new(|| unsafe {
    Library::new("/usr/lib/libssl.so").unwrap()
});
static SSL_CTRL_SYMBOLS: Lazy<SslCtrlSymbol<'static>> = Lazy::new(|| unsafe {
    OPENSSL.get(b"SSL_ctrl\0").unwrap()
});

#[no_mangle]
pub extern fn SSL_ctrl(ssl: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    const SSL_CTRL_SET_TLSEXT_HOSTNAME: usize = 55;

    if cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME as _ {
        1
    } else {
        (SSL_CTRL_SYMBOLS)(ssl, cmd, larg, parg)
    }
}
