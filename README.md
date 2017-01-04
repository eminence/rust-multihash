Multihash for Rust
=====

rust-multihash is an implementation of the [multihash algorithm](https://github.com/multiformats/multihash) that allows for multiple different hash algorithms to be contained in the same format. This makes it extensible as new hashing algorithms are added.

To use, add the following to your `Cargo.toml` file, as this crate is not published on crates.io:

```
[dependencies.rust-multihash]
git="https://github.com/eminence/rust-multihash"
```


Example
----
To get a SHA2-256 hash of a string:
```
use multihash::{HashType, multihash};

let hash = multihash(HashType::SHA2256, "Hello World".to_vec());
```

Contributing
----

This repository is a fork of a Google [repo](https://github.com/google/rust-multihash) that is no longer maintained.
Any contributions to the original fork require a Google Contributor License Agreement, but contributions to this fork do not (see that repo for more details).
Any contributions to this repo must be under the [Apache2 license](https://github.com/eminence/rust-multihash/blob/master/LICENSE.md).

