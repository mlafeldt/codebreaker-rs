# codebreaker-rs

[![Latest version](https://img.shields.io/crates/v/codebreaker.svg)](https://crates.io/crates/codebreaker)
[![Documentation](https://docs.rs/codebreaker/badge.svg)](https://docs.rs/codebreaker)
[![CI](https://github.com/mlafeldt/codebreaker-rs/workflows/Rust/badge.svg)](https://github.com/mlafeldt/codebreaker-rs/actions)

A Rust library to decrypt & encrypt any cheat code for CodeBreaker PS2.

Originally reverse-engineered from MIPS R5900 assembly and [converted to C](https://github.com/mlafeldt/cb2util/blob/v1.9/cb2_crypto.c) in 2006. Now ported to Rust for [fun and profit](https://github.com/mlafeldt/cb2util/pull/13).

## Quick Start

Add the crate as a dependency to your `Cargo.toml`:

```toml
[dependencies]
codebreaker = "0.1"
```

Now you can start decrypting some codes:

```rust
use codebreaker::Codebreaker;

let mut encrypted: Vec<(u32, u32)> = vec![
    (0x2AFF014C, 0x2411FFFF),
    (0xB4336FA9, 0x4DFEFB79),
    (0x973E0B2A, 0xA7D4AF10),
];
let decrypted: Vec<(u32, u32)> = vec![
    (0x2043AFCC, 0x2411FFFF),
    (0xBEEFC0DE, 0x00000000),
    (0x2096F5B8, 0x000000BE),
];

let mut cb = Codebreaker::new();
for code in encrypted.iter_mut() {
    cb.decrypt_code_mut(&mut code.0, &mut code.1);
}
assert_eq!(decrypted, encrypted);
```

Read the [full documentation](https://docs.rs/codebreaker) for more examples.

## License

Copyright (c) 2020 Mathias Lafeldt

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.
