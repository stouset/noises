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

    pub fn crypto_auth_hmacsha256_init(state: *mut crypto_auth_hmacsha256_state, key: *const u8, len: size_t);
    pub fn crypto_auth_hmacsha256_update(state: *mut crypto_auth_hmacsha256_state, message: *const u8, len: size_t);
    pub fn crypto_auth_hmacsha256_final(state: *mut crypto_auth_hmacsha256_state, hash: *mut u8);
}
