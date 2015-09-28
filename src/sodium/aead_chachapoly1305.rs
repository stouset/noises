use super::ffi::*;

use std::ptr;

pub type aead_chacha20poly1305_key     = [u8; 32];
pub type aead_chacha20poly1305_nonce   = [u8; 8];
pub type aead_chacha20poly1305_ad      = [u8];
pub type aead_chacha20poly1305_message = [u8];

const TAG_LEN : usize = 16;

pub fn aead_chacha20poly1305_ciphertext_len(len: usize) -> usize { len + TAG_LEN }
pub fn aead_chacha20poly1305_plaintext_len(len: usize)  -> usize { len - TAG_LEN }

pub fn aead_chacha20poly1305_decrypt(
    out:        &mut aead_chacha20poly1305_message,
    key:        &    aead_chacha20poly1305_key,
    nonce:      &    aead_chacha20poly1305_nonce,
    ad:         &    aead_chacha20poly1305_ad,
    ciphertext: &    aead_chacha20poly1305_message,
) -> bool {
    assert_eq!(
        out.len(),
        aead_chacha20poly1305_plaintext_len(ciphertext.len())
    );

    unsafe {
        0 == crypto_aead_chacha20poly1305_decrypt(
            out.as_mut_ptr(),
            ptr::null::<c_ulonglong>() as *mut _,
            ptr::null(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            ad.as_ptr(),
            ad.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    }
}

pub fn aead_chacha20poly1305_encrypt(
    out:       &mut aead_chacha20poly1305_message,
    key:       &    aead_chacha20poly1305_key,
    nonce:     &    aead_chacha20poly1305_nonce,
    ad:        &    aead_chacha20poly1305_ad,
    plaintext: &    aead_chacha20poly1305_message,
) -> bool {
    assert_eq!(
        out.len(),
        aead_chacha20poly1305_ciphertext_len(plaintext.len())
    );

    unsafe {
        0 == crypto_aead_chacha20poly1305_encrypt(
            out.as_mut_ptr(),
            ptr::null::<c_ulonglong>() as *mut _,
            plaintext.as_ptr(),
            plaintext.len() as c_ulonglong,
            ad.as_ptr(),
            ad.len() as c_ulonglong,
            ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    }
}
