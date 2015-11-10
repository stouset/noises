use super::ffi::*;

pub type scalarmult_curve25519_secretkey  = [u8; 32];
pub type scalarmult_curve25519_privatekey = [u8; 32];
pub type scalarmult_curve25519_publickey  = [u8; 32];

pub fn scalarmult_curve25519(
    out:     &mut scalarmult_curve25519_secretkey,
    public:  &    scalarmult_curve25519_publickey,
    private: &    scalarmult_curve25519_privatekey,
) {
    unsafe {
        let _ = crypto_scalarmult_curve25519(
            out    .as_mut_ptr(),
            public .as_ptr(),
            private.as_ptr(),
        );
    }
}

pub fn scalarmult_curve25519_base(
    out:     &mut scalarmult_curve25519_publickey,
    private: &    scalarmult_curve25519_privatekey,
) {
    unsafe {
        let _ = crypto_scalarmult_curve25519_base(
            out    .as_mut_ptr(),
            private.as_ptr(),
        );
    }
}
