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
    SHA1,
    SHA2256,
    SHA2512,
    SHA3,
    Blake2b,
    Blake2s
}

impl HashTypes {
    pub fn to_u8(&self) -> u8 {
        match *self {
            HashTypes::SHA1 => 0x11,
            HashTypes::SHA2256 => 0x12,
            HashTypes::SHA2512 => 0x13,
            HashTypes::SHA3 => 0x14,
            HashTypes::Blake2b => 0x40,
            HashTypes::Blake2s => 0x41,
        }
    }

    /// Try to interpret a byte as a possible HashType
    pub fn from_u8(b: u8) -> Option<HashTypes> {
        match b {
            0x11 => Some(HashTypes::SHA1),
            0x12 => Some(HashTypes::SHA2256),
            0x13 => Some(HashTypes::SHA2512),
            0x14 => Some(HashTypes::SHA3),
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
    let ssl_hash: Option<MessageDigest> = match wanthash {
        HashTypes::SHA1 => Some(MessageDigest::sha1()),
        HashTypes::SHA2256 => Some(MessageDigest::sha256()),
        HashTypes::SHA2512 => Some(MessageDigest::sha512()),
        _ => None,
    };
    match ssl_hash {
        Some(openssl_type) => {
            let mut temphash = hash(openssl_type, input.as_slice()).map_err(|e| e.description().to_owned())?;
            let length = temphash.len() as u8;
            temphash.insert(0, length);
            temphash.insert(0, wanthash.to_u8()); // Add the hashtype to the hash.
            Ok(temphash)
        }
        None => Err("Sorry, we don't support that hash algorithm yet.".to_string()),
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
}
