// Copyright 2015 Google, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::error::Error;

extern crate openssl;

use openssl::hash::{hash, MessageDigest};

/// List of types currently supported in Multihash.
/// SHA3, Blake2b, and Blake2s are not yet supported in OpenSSL, so are not available in rust-multihash.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum HashTypes {
    Identity,
    SHA1,
    SHA2256,
    SHA2512,
    SHA3, // SHA3 and SHA3512 are the same thing
    SHA3512,
    SHA3384,
    SHA3256,
    SHA3224,
    Shake128,
    Shake256,
    Blake2b,
    Blake2s
}

impl HashTypes {
    pub fn to_u8(&self) -> u8 {
        match *self {
            HashTypes::Identity => 0x00,
            HashTypes::SHA1 => 0x11,
            HashTypes::SHA2256 => 0x12,
            HashTypes::SHA2512 => 0x13,
            HashTypes::SHA3 | HashTypes::SHA3512=> 0x14,
            HashTypes::SHA3384 => 0x15,
            HashTypes::SHA3256 => 0x16,
            HashTypes::SHA3224 => 0x17,
            HashTypes::Shake128 => 0x18,
            HashTypes::Shake256 => 0x19,
            HashTypes::Blake2b => 0x40,
            HashTypes::Blake2s => 0x41,
        }
    }

    /// Try to interpret a byte as a possible HashType
    pub fn from_u8(b: u8) -> Option<HashTypes> {
        match b {
            0x00 => Some(HashTypes::Identity),
            0x11 => Some(HashTypes::SHA1),
            0x12 => Some(HashTypes::SHA2256),
            0x13 => Some(HashTypes::SHA2512),
            0x14 => Some(HashTypes::SHA3512),
            0x15 => Some(HashTypes::SHA3384),
            0x16 => Some(HashTypes::SHA3256),
            0x17 => Some(HashTypes::SHA3224),
            0x18 => Some(HashTypes::Shake128),
            0x19 => Some(HashTypes::Shake256),
            0x40 => Some(HashTypes::Blake2b),
            0x41 => Some(HashTypes::Blake2s),
            _ => None
        }
    }
}

/// Hashes the input using the given hash algorithm. Also adds the leading bytes for type of algo
/// and length of digest.
///
/// # Example
/// ```
/// use rust_multihash::{HashTypes, multihash};
///
/// let testphrase = b"Hello World";
/// let digest = multihash(HashTypes::SHA2512, testphrase.to_vec());
/// ```
pub fn multihash(wanthash: HashTypes, input: Vec<u8>) -> Result<Vec<u8>, String> {
    enum PrivHashType {
        OpenSSL(MessageDigest),
        Identity,
        None
    };

    let ssl_hash: PrivHashType = match wanthash {
        HashTypes::Identity => PrivHashType::Identity,
        HashTypes::SHA1 => PrivHashType::OpenSSL(MessageDigest::sha1()),
        HashTypes::SHA2256 => PrivHashType::OpenSSL(MessageDigest::sha256()),
        HashTypes::SHA2512 => PrivHashType::OpenSSL(MessageDigest::sha512()),
        _ => PrivHashType::None,
    };
    match ssl_hash {
        PrivHashType::OpenSSL(openssl_type) => {
            let mut temphash = hash(openssl_type, input.as_slice()).map_err(|e| e.description().to_owned())?;
            let length = temphash.len() as u8;
            temphash.insert(0, length);
            temphash.insert(0, wanthash.to_u8()); // Add the hashtype to the hash.
            Ok(temphash)
        }
        PrivHashType::Identity => {
            let in_len = input.len();
            let mut input = input;
            if input.len() > 255 {
                Err("Sorry, input is too long to support the identity hash".to_owned())
            } else {
                input.insert(0, in_len as u8);
                input.insert(0, wanthash.to_u8());
                Ok(input)
            }
        }
        PrivHashType::None => Err("Sorry, we don't support that hash algorithm yet.".to_string()),
    }
}

#[cfg(test)]
mod test {
    use super::{HashTypes, multihash};
    use openssl::hash::{hash, MessageDigest};

    #[test]
    fn test1() {
        let example = b"hello world";
        let mut result = hash(MessageDigest::sha256(), example).unwrap();
        let length = result.len() as u8;
        result.insert(0, 0x12);
        result.insert(1, length);

        assert_eq!(multihash(HashTypes::SHA2256, example.to_vec()).unwrap(), result);
        println!("hello world hashes to: {:?}", result);

        assert_eq!(HashTypes::from_u8(0x12), Some(HashTypes::SHA2256));
        assert_eq!(HashTypes::from_u8(0x01), None);
    }

    #[test]
    fn test_id() {
        assert_eq!(multihash(HashTypes::Identity, b"hello".to_vec()).unwrap(), b"\x00\x05hello");
    }
}
