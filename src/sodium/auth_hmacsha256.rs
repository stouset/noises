use super::ffi::*;

pub type auth_hmacsha256_key  = [u8];
pub type auth_hmacsha256_data = [u8];
pub type auth_hmacsha256_hmac = [u8; 32];

pub fn auth_hmacsha256(
    hmac:  &mut auth_hmacsha256_hmac,
    key:   &    auth_hmacsha256_key,
    data:  &    auth_hmacsha256_data,
) {
    unsafe {
        crypto_auth_hmacsha256(
            hmac.as_mut_ptr(),
            data.as_ptr(),
            data.len() as size_t,
            key .as_ptr(),
        );
    }
}
