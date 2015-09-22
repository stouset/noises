use super::ffi::*;

use secrets::Secret;

type auth_hmacsha256_state = Secret<crypto_auth_hmacsha256_state>;

pub type auth_hmacsha256_key  = [u8];
pub type auth_hmacsha256_data = [u8];
pub type auth_hmacsha256_hmac = [u8; 32];

pub fn auth_hmacsha256(
    key:  &    auth_hmacsha256_key,
    data: &    auth_hmacsha256_data,
    hmac: &mut auth_hmacsha256_hmac,
) {
    let mut state   = unsafe { auth_hmacsha256_state::uninitialized() };
    let mut state_w = state.borrow_mut();

    unsafe {
        crypto_auth_hmacsha256_init(
            &mut *state_w,
            key.as_ptr(),
            key.len() as size_t,
        );

        crypto_auth_hmacsha256_update(
            &mut *state_w,
            data.as_ptr(),
            data.len() as size_t,
        );

        crypto_auth_hmacsha256_final(
            &mut *state_w,
            hmac.as_mut_ptr(),
        );
    }
}
