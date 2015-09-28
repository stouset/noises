use super::ffi::*;

pub type stream_chacha20_key     = [u8; 32];
pub type stream_chacha20_nonce   = [u8; 8];
pub type stream_chacha20_message = [u8];

pub fn stream_chacha20_xor(
    out:     &mut stream_chacha20_message,
    key:     &    stream_chacha20_key,
    nonce:   &    stream_chacha20_nonce,
    message: &    stream_chacha20_message,
) {
    unsafe {
        let _ = crypto_stream_chacha20_xor(
            out    .as_mut_ptr(),
            message.as_ptr(),
            message.len() as size_t,
            nonce  .as_ptr(),
            key    .as_ptr(),
        );
    }
}
