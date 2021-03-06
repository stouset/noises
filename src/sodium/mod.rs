// This comment prevents Emacs from thinking this file is executable
#![allow(unsafe_code)]
#![allow(non_camel_case_types)]

mod ffi;

mod aead_chachapoly1305;
mod auth_hmacsha256;
mod hash_sha256;
mod stream_chacha20;

pub use self::aead_chachapoly1305::*;
pub use self::auth_hmacsha256::*;
pub use self::hash_sha256::*;
pub use self::stream_chacha20::*;

use std::sync::{Once, ONCE_INIT};

static INIT: Once = ONCE_INIT;

pub fn init() {
    INIT.call_once(|| {
        if unsafe { ffi::sodium_init() } < 0 {
            panic!("sodium: couldn't initialize libsodium");
        }
    })
}
