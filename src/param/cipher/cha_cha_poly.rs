pub use super::{Cipher, Key, Nonce, Digest};

use sodium;

pub struct ChaChaPoly;

impl Cipher for ChaChaPoly {
    #[allow(unsafe_code)]
    fn hmac_hash(key: &Key, data: &[u8]) -> Key {
        unsafe {
            Key::new(|out| {
                sodium::auth_hmacsha256(
                    &key.borrow()[..],
                    data,
                    out,
                );
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_hmac_hash_1() {
        let mut key    = *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let     data   =  b"";
        let     vector =  b"\xb6\x13\x67\x9a\x08\x14\xd9\xec\x77\x2f\x95\xd7\x78\xc3\x5f\xc5\xff\x16\x97\xc4\x93\x71\x56\x53\xc6\xc7\x12\x14\x42\x92\xc5\xad";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_2() {
        let mut key    = *b"\x4f\xc8\x00\x33\x47\xd0\x33\xf5\xd6\x1b\xbd\x88\xab\x78\xcf\xab\x0d\x2f\xe5\x4e\xd6\x85\xd3\x6e\x86\xfa\x76\x3e\x6c\xa0\xf1\x19";
        let     data   =  b"\x50\x8d\xa3\x0a\xe2\x28\xc7\x7e\xd5\x90\xec\xc1\x09\x71\x98\x73\x62\x7f\x99\x4b\x65\xa7\x71\x3a\x48\x82\xed\x3d\xfb\xb1\x3b\x14";
        let     vector =  b"\x19\x2a\x17\x95\x3f\x58\x6d\x80\x93\xcd\xf7\x78\xd7\x31\x94\xfe\x63\x85\xf4\xee\xd0\xc7\xbe\x56\xa6\xfe\xd6\x0e\xf5\xf4\xcb\x60";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    fn test_vector_hmac_hash(key: &mut [u8; 32], data: &[u8], vector: &[u8; 32]) {
        let key    = Key::from(key);
        let result = ChaChaPoly::hmac_hash(&key, data);

        assert_eq!(*vector, *result.borrow());
    }
}
