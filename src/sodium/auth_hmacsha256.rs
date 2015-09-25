use super::ffi::*;

pub type auth_hmacsha256_state = crypto_auth_hmacsha256_state;
pub type auth_hmacsha256_key   = [u8];
pub type auth_hmacsha256_data  = [u8];
pub type auth_hmacsha256_hmac  = [u8; 32];

pub fn auth_hmacsha256(
    state: &mut auth_hmacsha256_state,
    hmac:  &mut auth_hmacsha256_hmac,
    key:   &    auth_hmacsha256_key,
    data:  &    auth_hmacsha256_data,
) {
    unsafe {
        crypto_auth_hmacsha256_init(
            state,
            key.as_ptr(),
            key.len() as size_t,
        );

        crypto_auth_hmacsha256_update(
            state,
            data.as_ptr(),
            data.len() as size_t,
        );

        crypto_auth_hmacsha256_final(
            state,
            hmac.as_mut_ptr(),
        );
    }
}
