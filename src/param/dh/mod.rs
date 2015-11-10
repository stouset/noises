use secrets::Secret;

mod curve_25519;
// mod curve_448;

pub use self::curve_25519::Curve25519;
// pub use self::curve_448::Curve448;

pub trait DH {
    type SecretKey  = (Secret<Self::Key>);
    type PrivateKey = (Secret<Self::Key>);
    type PublicKey  = (Self::Key);

    type Key;

    fn generate_keypair() -> (Self::PrivateKey, Self::PublicKey);
    fn dh(private: &Self::PrivateKey, public: &Self::PublicKey) -> Self::SecretKey;
}
