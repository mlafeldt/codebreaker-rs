# codebreaker-rs

[![Latest version](https://img.shields.io/crates/v/codebreaker.svg)](https://crates.io/crates/codebreaker)
[![Documentation](https://docs.rs/codebreaker/badge.svg)](https://docs.rs/codebreaker)
[![CI](https://github.com/mlafeldt/codebreaker-rs/workflows/CI/badge.svg)](https://github.com/mlafeldt/codebreaker-rs/actions)

A Rust library to decrypt & encrypt any cheat code for CodeBreaker PS2.

## Quickstart

Add the crate as a dependency to your `Cargo.toml`:

```toml
[dependencies]
codebreaker = "0.4"
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

## Platform support

The `codebreaker` crate is `no_std` and currently supports little-endian targets only.
The CB v7 implementation intentionally preserves byte-level behavior from the original C code.

## History

- **2006**: I cracked the CodeBreaker PS2 v7 code encryption by reverse-engineering MIPS R5900 assembly and [converting it to C](https://github.com/mlafeldt/cb2util/blob/v1.9/cb2_crypto.c).
  The first v7 codes were decrypted on March 8, and [CB2crypt](https://github.com/mlafeldt/CB2crypt), a Windows tool built on that code, followed on March 23.
- **2007**: The code moved on to [cb2util](https://github.com/mlafeldt/cb2util), first released in April and extended until 2013 to handle CodeBreaker's file formats.
- **2020**: [Ported to Rust](https://github.com/mlafeldt/cb2util/pull/13) for fun and profit and published as this crate.
  I wrote about it in [7 Things I Learned From Porting a C Crypto Library to Rust](https://web.archive.org/web/20241119103347/https://sharpend.io/7-things-i-learned-from-porting-a-c-crypto-library-to-rust/).
- **2026**: Checked against the CodeBreaker v9.2 firmware with the help of AI.
  Its decryption code was decompiled and run in an emulator side by side with this crate on more than 10,000 code lines.
  This found two regressions in 0.4.0 and two older bugs, all fixed now, and added support for the `FFFFFFFF` lines that turn CB v7 off.
  A quirk in the firmware's RSA code and a rarely used encryption option are left out on purpose and explained in the code.

## License

Copyright (c) Mathias Lafeldt

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.
