use super::ffi::*;

pub type hash_sha256_data   = [u8];
pub type hash_sha256_digest = [u8; 32];

pub fn hash_sha256(
    digest: &mut hash_sha256_digest,
    data:   &    hash_sha256_data,
) {
    unsafe {
        let _ = crypto_hash_sha256(
            digest.as_mut_ptr(),
            data  .as_ptr(),
            data  .len() as size_t,
        );
    }
}
