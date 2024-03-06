# codebreaker-rs

[![Latest version](https://img.shields.io/crates/v/codebreaker.svg)](https://crates.io/crates/codebreaker)
[![Documentation](https://docs.rs/codebreaker/badge.svg)](https://docs.rs/codebreaker)
[![CI](https://github.com/mlafeldt/codebreaker-rs/workflows/CI/badge.svg)](https://github.com/mlafeldt/codebreaker-rs/actions)

A Rust library to decrypt & encrypt any cheat code for CodeBreaker PS2.

Originally reverse-engineered from MIPS R5900 assembly and [converted to C](https://github.com/mlafeldt/cb2util/blob/v1.9/cb2_crypto.c) in 2006. Now ported to Rust for [fun and profit](https://github.com/mlafeldt/cb2util/pull/13).

For more information, check out my article on [7 Things I Learned From Porting a C Crypto Library to Rust](https://sharpend.io/7-things-i-learned-from-porting-a-c-crypto-library-to-rust/).

## Quickstart

Add the crate as a dependency to your `Cargo.toml`:

```toml
[dependencies]
codebreaker = "0.3"
```

Now you can start decrypting some codes:

```rust
use codebreaker::Codebreaker;

let input: Vec<(u32, u32)> = vec![
    (0x2043AFCC, 0x2411FFFF),
    (0x2A973DBD, 0x00000000),
    (0xB4336FA9, 0x4DFEFB79),
    (0x973E0B2A, 0xA7D4AF10),
];
let output: Vec<(u32, u32)> = vec![
    (0x2043AFCC, 0x2411FFFF),
    (0x201F6024, 0x00000000),
    (0xBEEFC0DE, 0x00000000),
    (0x2096F5B8, 0x000000BE),
];

let mut cb = Codebreaker::new();
for (i, code) in input.iter().enumerate() {
    assert_eq!(cb.auto_decrypt_code(code.0, code.1), output[i]);
}
```

Read the [full documentation](https://docs.rs/codebreaker) for more examples.

## `no_std` support

The `codebreaker` crate has a Cargo feature named "std" that is enabled by default. In order to use the crate on embedded systems, this feature needs to be disabled:

```toml
[dependencies]
codebreaker = { version = "0.3", default-features = false }
```

## License

Copyright (c) 2020-2024 Mathias Lafeldt

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.
