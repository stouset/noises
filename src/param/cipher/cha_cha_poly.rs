pub use super::{Cipher, Key, Nonce, Digest};

use sodium;

use std::cell::RefCell;
use std::mem;

use secrets::Secret;

pub struct ChaChaPoly {
    hash_state: RefCell<Secret<sodium::hash_sha256_state>>,
    hmac_state: RefCell<Secret<sodium::auth_hmacsha256_state>>,
}

#[allow(unsafe_code)]
impl ChaChaPoly {
    fn new() -> Self {
        ChaChaPoly {
            hash_state: RefCell::new(unsafe { Secret::uninitialized() }),
            hmac_state: RefCell::new(unsafe { Secret::uninitialized() }),
        }
    }
}

#[allow(unsafe_code)]
impl Cipher for ChaChaPoly {
    fn hash(&self, data: &[u8]) -> Digest {
        let mut out     = unsafe { mem::uninitialized() };
        let mut state   = self.hash_state.borrow_mut();
        let     state_w = &mut state     .borrow_mut();

        sodium::hash_sha256(state_w, &mut out, data);

        out
    }

    fn hmac_hash(&self, key: &Key, data: &[u8]) -> Key {
        let mut state   = self.hmac_state.borrow_mut();
        let     state_w = &mut state     .borrow_mut();
        let     key_r   = &    key       .borrow()[..];

        unsafe {
            Key::new(|out_w| sodium::auth_hmacsha256(state_w, out_w, key_r, data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_hash_1() {
        let data   = b"abc";
        let vector = b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";

        test_vector_hash(data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_1() {
        let mut key    = *b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let     data   =  b"Hi There";
        let     vector =  b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_2() {
        let mut key    = *b"Jefe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let     data   =  b"what do ya want for nothing?";
        let     vector =  b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_3() {
        let mut key    = *b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let     data   =  b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";
        let     vector =  b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_4() {
        let mut key    = *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x00\x00\x00\x00\x00\x00\x00";
        let     data   =  b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";
        let     vector =  b"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_5() {
        let mut key    = *b"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let     data   =  b"Test With Truncation";
        let     vector =  b"\xa3\xb6\x16\x74\x73\x10\x0e\xe0\x6e\x0c\x79\x6c\x29\x55\x55\x2b\xfa\x6f\x7c\x0a\x6a\x8a\xef\x8b\x93\xf8\x60\xaa\xb0\xcd\x20\xc5";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_6() {
        let mut key    = *b"\x45\xad\x4b\x37\xc6\xe2\xfc\x0a\x2c\xfc\xc1\xb5\xda\x52\x41\x32\xec\x70\x76\x15\xc2\xca\xe1\xdb\xbc\x43\xc9\x7a\xa5\x21\xdb\x81";
        let     data   =  b"Test Using Larger Than Block-Size Key - Hash Key First";
        let     vector =  b"\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    #[test]
    fn test_vector_hmac_hash_7() {
        let mut key    = *b"\x45\xad\x4b\x37\xc6\xe2\xfc\x0a\x2c\xfc\xc1\xb5\xda\x52\x41\x32\xec\x70\x76\x15\xc2\xca\xe1\xdb\xbc\x43\xc9\x7a\xa5\x21\xdb\x81";
        let     data   =  b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let     vector =  b"\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2";

        test_vector_hmac_hash(&mut key, data, vector);
    }

    fn test_vector_hash(data: &[u8], vector: &[u8; 32]) {
        let result = ChaChaPoly::new().hash(data);

        assert_eq!(*vector, result);
    }

    fn test_vector_hmac_hash(key: &mut [u8; 32], data: &[u8], vector: &[u8; 32]) {
        let key    = Key::from(key);
        let result = ChaChaPoly::new().hmac_hash(&key, data);

        assert_eq!(*vector, *result.borrow());
    }
}
