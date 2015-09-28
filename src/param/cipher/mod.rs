use secrets::{Secret, SecretVec};

mod cha_cha_poly;

pub use self::cha_cha_poly::ChaChaPoly;
pub type Key       = Secret<[u8; 32]>;
pub type Plaintext = SecretVec<u8>;
pub type Nonce     = [u8; 8];
pub type Digest    = [u8; 32];

//impl Nonce {
//    pub fn increment(&mut self) {
//        sodium::increment(self);
//    }
//}

pub trait Cipher {
    // fn encrypt(key: &Key, nonce: &Nonce, ad: &[u8], plaintext:  &Plaintext) -> Vec<u8>;
    // fn decrypt(key: &Key, nonce: &Nonce, ad: &[u8], ciphertext: &[u8])      -> Plaintext;
    fn getkey(key: &Key, nonce: &Nonce) -> Key;
    fn hash(data: &[u8]) -> Digest;
    fn hmac_hash(key: &Key, data: &[u8]) -> Key;
}
