use secrets::Secret;

mod cha_cha_poly;

pub use self::cha_cha_poly::ChaChaPoly;

pub type Key        = Secret<[u8; 32]>;
pub type Nonce      = [u8; 8];
pub type Digest     = [u8; 32];

pub trait Cipher {
    // fn encrypt(key: &Key, nonce: &Nonce, ad: &[u8], plaintext:  &SecretVec<u8>) -> Vec<u8>;
    // fn decrypt(key: &Key, nonce: &Nonce, ad: &[u8], ciphertext: &[u8])          -> SecretVec<u8>;
    // fn getkey(key: &Key, nonce: &Nonce) -> Key;
    // fn hash(data: &[u8]) -> Digest;
    fn hmac_hash(key: &Key, data: &[u8]) -> Key;
}
