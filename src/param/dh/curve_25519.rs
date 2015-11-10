use super::DH;

use sodium;

use std::mem;

pub struct Curve25519;

impl DH for Curve25519 {
    type Key = [u8; 32];

    fn generate_keypair() -> (Self::PrivateKey, Self::PublicKey) {
        let mut public  : Self::PublicKey  = unsafe { mem::uninitialized() };
        let     private : Self::PrivateKey = Self::PrivateKey::random();

        sodium::scalarmult_curve25519_base(
            &mut public,
            &private.borrow(),
        );

        (private, public)
    }

    fn dh(private: &Self::PrivateKey, public: &Self::PublicKey) -> Self::SecretKey {
        unsafe {
            Self::SecretKey::new(|out| {
                sodium::scalarmult_curve25519(
                    out,
                    &public,
                    &private.borrow()
                );
            })
        }
    }
}
