use super::ffi::*;

pub type hash_sha256_state  = crypto_hash_sha256_state;
pub type hash_sha256_data   = [u8];
pub type hash_sha256_digest = [u8; 32];

pub fn hash_sha256(
    state:  &mut hash_sha256_state,
    digest: &mut hash_sha256_digest,
    data:   &    hash_sha256_data,
) {
    unsafe {
        crypto_hash_sha256_init(
            state,
        );

        crypto_hash_sha256_update(
            state,
            data.as_ptr(),
            data.len() as size_t
        );

        crypto_hash_sha256_final(
            state,
            digest.as_mut_ptr(),
        );
    }
}
