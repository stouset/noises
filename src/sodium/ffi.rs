pub use libc::{c_void, c_int, c_ulonglong};

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

    pub fn crypto_aead_chacha20poly1305_decrypt(
        m:      *mut   u8,
        m_len:  *mut   c_ulonglong,
        n_sec:  *const u8,
        c:      *const u8,
        c_len:  c_ulonglong,
        ad:     *const u8,
        ad_len: c_ulonglong,
        n_pub:  *const u8,
        k:      *const u8,
    ) -> c_int;

    pub fn crypto_aead_chacha20poly1305_encrypt(
        c:      *mut   u8,
        c_len:  *mut   c_ulonglong,
        m:      *const u8,
        m_len:  c_ulonglong,
        ad:     *const u8,
        ad_len: c_ulonglong,
        n_sec:  *const u8,
        n_pub:  *const u8,
        k:      *const u8,
    ) -> c_int;

    pub fn crypto_auth_hmacsha256(
        out:  *mut   u8,
        data: *const u8,
        len:  c_ulonglong,
        key:  *const u8,
    ) -> c_int;


    pub fn crypto_hash_sha256(
        out:  *mut u8,
        data: *const u8,
        len:  c_ulonglong,
    ) -> c_int;

    pub fn crypto_stream_chacha20(
        out:     *mut u8,
        len:     c_ulonglong,
        nonce:   *const u8,
        key:     *const u8,
    ) -> c_int;
}
