use lazy_static::lazy_static;
use libc::{ c_int, c_long, c_void };
use libloading::{ Library, Symbol };


const SSL_CTRL_SET_TLSEXT_HOSTNAME: usize = 55;

lazy_static! {
    static ref OPENSSL: Library = Library::new("/usr/lib/libssl.so").unwrap();
}

#[no_mangle]
pub extern fn SSL_ctrl(ssl: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    if cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME as _ {
        1
    } else {
        unsafe {
            let foo: Symbol<fn(ssl: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long> =
                OPENSSL.get(b"SSL_ctrl\0").unwrap();
            foo(ssl, cmd, larg, parg)
        }
    }
}
