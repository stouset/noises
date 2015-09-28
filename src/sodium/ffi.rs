pub use libc::{c_void, c_int, size_t};

use secrets::Zeroable;

#[repr(C)]
pub struct crypto_hash_sha256_state {
    state: [u32; 8],
    count: u64,
    buf:   [u8; 64],
}

#[repr(C)]
pub struct crypto_auth_hmacsha256_state {
    ictx: crypto_hash_sha256_state,
    octx: crypto_hash_sha256_state,
}

impl Zeroable for crypto_hash_sha256_state {}
impl Zeroable for crypto_auth_hmacsha256_state {}

#[link(name="sodium")]
extern {
    pub fn sodium_init() -> c_int;

    pub fn crypto_auth_hmacsha256(
        out:  *mut   u8,
        data: *const u8,
        len: size_t,
        key:  *const u8,
    ) -> c_int;


    pub fn crypto_hash_sha256(
        out:  *mut u8,
        data: *const u8,
        len:  size_t
    ) -> c_int;

    pub fn crypto_stream_chacha20_xor(
        out:     *mut   u8,
        message: *const u8,
        len:     size_t,
        nonce:   *const u8,
        key:     *const u8,
    ) -> c_int;
}
