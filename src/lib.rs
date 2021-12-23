//! Encrypt and decrypt cheat codes for all versions of CodeBreaker PS2.
//!
//! Uses [cb1](cb1/index.html) and [cb7](cb7/index.html) under the hood to
//! support both CB v1 and v7 codes.
//!
//! # Quickstart
//!
//! ```
//! use codebreaker::Codebreaker;
//!
//! let input: Vec<(u32, u32)> = vec![
//!     (0x2043AFCC, 0x2411FFFF),
//!     (0x2A973DBD, 0x00000000),
//!     (0xB4336FA9, 0x4DFEFB79),
//!     (0x973E0B2A, 0xA7D4AF10),
//! ];
//! let output: Vec<(u32, u32)> = vec![
//!     (0x2043AFCC, 0x2411FFFF),
//!     (0x201F6024, 0x00000000),
//!     (0xBEEFC0DE, 0x00000000),
//!     (0x2096F5B8, 0x000000BE),
//! ];
//!
//! let mut cb = Codebreaker::new();
//! for (i, code) in input.iter().enumerate() {
//!     assert_eq!(cb.auto_decrypt_code(code.0, code.1), output[i]);
//! }
//! ```

#![deny(clippy::all, clippy::nursery)]
#![deny(nonstandard_style, rust_2018_idioms)]
#![deny(missing_docs, missing_debug_implementations)]
#![forbid(unsafe_code)]
#![no_std]

#[cfg(doctest)]
doc_comment::doctest!("../README.md", readme);

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        extern crate std;
        mod std_alloc {
            pub use std::{
                fmt,
                string::{String, ToString},
                vec,
                vec::Vec,
            };
        }
    } else {
        extern crate alloc;
        mod std_alloc {
            pub use alloc::{
                fmt,
                string::{String, ToString},
                vec,
                vec::Vec,
            };
        }
    }
}

pub mod cb1;
pub mod cb7;
mod rc4;

use cb7::{is_beefcode, Cb7};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Scheme {
    Raw,
    V1,
    V7,
}

/// A processor for CB v1 and v7 codes.
#[derive(Debug, Clone, Copy)]
pub struct Codebreaker {
    scheme: Scheme,
    cb7: Cb7,
    code_lines: usize,
}

/// Does the same as [`new`](#method.new).
impl Default for Codebreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl Codebreaker {
    /// Returns a new processor for encrypting and decrypting a list of CB v1
    /// and v7 codes.
    pub const fn new() -> Self {
        Self {
            scheme: Scheme::Raw,
            cb7: Cb7::new(),
            code_lines: 0,
        }
    }

    /// Returns a new processor for all CB v7 codes published on CMGSCCC.com.
    ///
    /// Lets you omit `B4336FA9 4DFEFB79` as the first code in the list.
    pub fn new_v7() -> Self {
        Self {
            scheme: Scheme::V7,
            cb7: Cb7::default(),
            code_lines: 0,
        }
    }

    /// Encrypts a code and returns the result.
    ///
    /// # Example
    /// ```
    /// use codebreaker::Codebreaker;
    ///
    /// let mut cb = Codebreaker::new();
    /// let code = cb.encrypt_code(0x2043AFCC, 0x2411FFFF);
    /// assert_eq!(code, (0x2AFF014C, 0x2411FFFF));
    /// ```
    pub fn encrypt_code(&mut self, addr: u32, val: u32) -> (u32, u32) {
        let mut code = (addr, val);
        self.encrypt_code_mut(&mut code.0, &mut code.1);
        code
    }

    /// Encrypts a code directly.
    ///
    /// # Example
    /// ```
    /// use codebreaker::Codebreaker;
    ///
    /// let mut cb = Codebreaker::new();
    /// let mut code = (0x2043AFCC, 0x2411FFFF);
    /// cb.encrypt_code_mut(&mut code.0, &mut code.1);
    /// assert_eq!(code, (0x2AFF014C, 0x2411FFFF));
    /// ```
    pub fn encrypt_code_mut(&mut self, addr: &mut u32, val: &mut u32) {
        let (oldaddr, oldval) = (*addr, *val);

        if self.scheme == Scheme::V7 {
            self.cb7.encrypt_code_mut(addr, val);
        } else {
            cb1::encrypt_code_mut(addr, val);
        }

        if is_beefcode(oldaddr) {
            self.cb7.beefcode(oldaddr, oldval);
            self.scheme = Scheme::V7;
        }
    }

    /// Decrypts a code and returns the result.
    ///
    /// # Example
    /// ```
    /// use codebreaker::Codebreaker;
    ///
    /// let encrypted: Vec<(u32, u32)> = vec![
    ///     (0x2AFF014C, 0x2411FFFF),
    ///     (0xB4336FA9, 0x4DFEFB79),
    ///     (0x973E0B2A, 0xA7D4AF10),
    /// ];
    /// let decrypted: Vec<(u32, u32)> = vec![
    ///     (0x2043AFCC, 0x2411FFFF),
    ///     (0xBEEFC0DE, 0x00000000),
    ///     (0x2096F5B8, 0x000000BE),
    /// ];
    ///
    /// let mut cb = Codebreaker::new();
    /// for (i, code) in encrypted.iter().enumerate() {
    ///     let result = cb.decrypt_code(code.0, code.1);
    ///     assert_eq!(result, decrypted[i]);
    /// }
    /// ```
    pub fn decrypt_code(&mut self, addr: u32, val: u32) -> (u32, u32) {
        let mut code = (addr, val);
        self.decrypt_code_mut(&mut code.0, &mut code.1);
        code
    }

    /// Decrypts a code directly.
    ///
    /// # Example
    /// ```
    /// use codebreaker::Codebreaker;
    ///
    /// let mut encrypted: Vec<(u32, u32)> = vec![
    ///     (0x2AFF014C, 0x2411FFFF),
    ///     (0xB4336FA9, 0x4DFEFB79),
    ///     (0x973E0B2A, 0xA7D4AF10),
    /// ];
    /// let decrypted: Vec<(u32, u32)> = vec![
    ///     (0x2043AFCC, 0x2411FFFF),
    ///     (0xBEEFC0DE, 0x00000000),
    ///     (0x2096F5B8, 0x000000BE),
    /// ];
    ///
    /// let mut cb = Codebreaker::new();
    /// for code in encrypted.iter_mut() {
    ///     cb.decrypt_code_mut(&mut code.0, &mut code.1);
    /// }
    /// assert_eq!(encrypted, decrypted);
    /// ```
    pub fn decrypt_code_mut(&mut self, addr: &mut u32, val: &mut u32) {
        if self.scheme == Scheme::V7 {
            self.cb7.decrypt_code_mut(addr, val);
        } else {
            cb1::decrypt_code_mut(addr, val);
        }

        if is_beefcode(*addr) {
            self.cb7.beefcode(*addr, *val);
            self.scheme = Scheme::V7;
        }
    }

    /// Smart version of [`decrypt_code`](#method.decrypt_code) that detects if
    /// and how a code needs to be decrypted.
    ///
    /// # Example
    /// ```
    /// use codebreaker::Codebreaker;
    ///
    /// let input: Vec<(u32, u32)> = vec![
    ///     (0x2043AFCC, 0x2411FFFF),
    ///     (0x2A973DBD, 0x00000000),
    ///     (0xB4336FA9, 0x4DFEFB79),
    ///     (0x973E0B2A, 0xA7D4AF10),
    /// ];
    /// let output: Vec<(u32, u32)> = vec![
    ///     (0x2043AFCC, 0x2411FFFF),
    ///     (0x201F6024, 0x00000000),
    ///     (0xBEEFC0DE, 0x00000000),
    ///     (0x2096F5B8, 0x000000BE),
    /// ];
    ///
    /// let mut cb = Codebreaker::new();
    /// for (i, code) in input.iter().enumerate() {
    ///     assert_eq!(cb.auto_decrypt_code(code.0, code.1), output[i]);
    /// }
    /// ```
    pub fn auto_decrypt_code(&mut self, addr: u32, val: u32) -> (u32, u32) {
        let mut code = (addr, val);
        self.auto_decrypt_code_mut(&mut code.0, &mut code.1);
        code
    }

    /// Smart version of [`decrypt_code_mut`](#method.decrypt_code_mut) that
    /// detects if and how a code needs to be decrypted.
    pub fn auto_decrypt_code_mut(&mut self, addr: &mut u32, val: &mut u32) {
        if self.scheme != Scheme::V7 {
            if self.code_lines == 0 {
                self.code_lines = num_code_lines(*addr);
                if (*addr >> 24) & 0x0e != 0 {
                    if is_beefcode(*addr) {
                        // ignore raw beefcode
                        self.code_lines -= 1;
                        return;
                    } else {
                        self.scheme = Scheme::V1;
                        self.code_lines -= 1;
                        cb1::decrypt_code_mut(addr, val);
                    }
                } else {
                    self.scheme = Scheme::Raw;
                    self.code_lines -= 1;
                }
            } else {
                self.code_lines -= 1;
                if self.scheme == Scheme::Raw {
                    return;
                }
                cb1::decrypt_code_mut(addr, val);
            }
        } else {
            self.cb7.decrypt_code_mut(addr, val);
            if self.code_lines == 0 {
                self.code_lines = num_code_lines(*addr);
                if self.code_lines == 1 && *addr == 0xffff_ffff {
                    // XXX: changing encryption via "FFFFFFFF 000xnnnn" is not supported
                    self.code_lines = 0;
                    return;
                }
            }
            self.code_lines -= 1;
        }

        if is_beefcode(*addr) {
            self.cb7.beefcode(*addr, *val);
            self.scheme = Scheme::V7;
            self.code_lines = 1;
        }
    }
}

const fn num_code_lines(addr: u32) -> usize {
    let cmd = addr >> 28;

    if cmd < 3 || cmd > 6 {
        1
    } else if cmd == 3 {
        if addr & 0x0040_0000 != 0 {
            2
        } else {
            1
        }
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Code;
    use crate::std_alloc::{vec, ToString, Vec};
    #[cfg(feature = "std")]
    use pretty_assertions::assert_eq;

    struct Test {
        cb: Codebreaker,
        decrypted: Vec<&'static str>,
        encrypted: Vec<&'static str>,
    }

    #[rustfmt::skip]
    fn tests() -> Vec<Test> {
        vec![
            Test {
                cb: Codebreaker::new(),
                decrypted: vec![
                    "2043AFCC 2411FFFF",
                    "BEEFC0DE 00000000",
                    "2096F5B8 000000BE",
                ],
                encrypted: vec![
                    "2AFF014C 2411FFFF",
                    "B4336FA9 4DFEFB79",
                    "973E0B2A A7D4AF10",
                ],
            },
            Test {
                cb: Codebreaker::new_v7(),
                decrypted: vec![
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
                encrypted: vec![
                    "D08F3A49 00078A53",
                    "3818DDE5 E72B2B16",
                    "973E0B2A A7D4AF10",
                ],
            },
            Test {
                cb: Codebreaker::default(),
                decrypted: vec![
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
                encrypted: vec![
                    "9A545CC6 188CBCFB",
                    "2A973DBD 00000000",
                    "2A03B60A 000000BE",
                ],
            },
        ]
    }

    #[test]
    fn test_encrypt_code() {
        for t in tests().iter_mut() {
            for (i, &line) in t.decrypted.iter().enumerate() {
                let code = Code::from(line);
                let result = t.cb.encrypt_code(code.0, code.1);
                assert_eq!(Code::from(result).to_string(), t.encrypted[i]);
            }
        }
    }

    #[test]
    fn test_encrypt_code_mut() {
        for t in tests().iter_mut() {
            for (i, &line) in t.decrypted.iter().enumerate() {
                let mut code = Code::from(line);
                t.cb.encrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(code.to_string(), t.encrypted[i]);
            }
        }
    }

    #[test]
    fn test_decrypt_code() {
        for t in tests().iter_mut() {
            for (i, &line) in t.encrypted.iter().enumerate() {
                let code = Code::from(line);
                let result = t.cb.decrypt_code(code.0, code.1);
                assert_eq!(Code::from(result).to_string(), t.decrypted[i]);
            }
        }
    }

    #[test]
    fn test_decrypt_code_mut() {
        for t in tests().iter_mut() {
            for (i, &line) in t.encrypted.iter().enumerate() {
                let mut code = Code::from(line);
                t.cb.decrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(code.to_string(), t.decrypted[i]);
            }
        }
    }

    struct AutoTest {
        input: Vec<&'static str>,
        output: Vec<&'static str>,
    }

    #[rustfmt::skip]
    fn auto_tests() -> Vec<AutoTest> {
        vec![
            AutoTest {
                // raw
                input: vec![
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
                output: vec![
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
            },
            AutoTest {
                // v1 encrypted
                input: vec![
                    "9A545CC6 188CBCFB",
                    "2A973DBD 00000000",
                    "2A03B60A 000000BE",
                ],
                output: vec![
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
            },
            AutoTest {
                // v7 encrypted
                input: vec![
                    "B4336FA9 4DFEFB79",
                    "D08F3A49 00078A53",
                    "3818DDE5 E72B2B16",
                    "973E0B2A A7D4AF10",
                ],
                output: vec![
                    "BEEFC0DE 00000000",
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
            },
            AutoTest {
                // v1 and v7 encrypted
                input: vec![
                    "9A545CC6 188CBCFB",
                    "2A973DBD 00000000",
                    "B4336FA9 4DFEFB79",
                    "973E0B2A A7D4AF10",
                ],
                output: vec![
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "BEEFC0DE 00000000",
                    "2096F5B8 000000BE",
                ],
            },
            AutoTest {
                // raw, v1, and v7 encrypted
                input: vec![
                    "9029BEAC 0C0A9225",
                    "2A973DBD 00000000",
                    "B4336FA9 4DFEFB79",
                    "973E0B2A A7D4AF10",
                ],
                output: vec![
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "BEEFC0DE 00000000",
                    "2096F5B8 000000BE",
                ],
            },
        ]
    }

    #[test]
    fn test_auto_decrypt_code() {
        for t in auto_tests().iter_mut() {
            let mut cb = Codebreaker::new();
            for (i, &line) in t.input.iter().enumerate() {
                let code = Code::from(line);
                let result = cb.auto_decrypt_code(code.0, code.1);
                assert_eq!(Code::from(result).to_string(), t.output[i]);
            }
        }
    }

    #[test]
    fn test_auto_decrypt_code_mut() {
        for t in auto_tests().iter_mut() {
            let mut cb = Codebreaker::new();
            for (i, &line) in t.input.iter().enumerate() {
                let mut code = Code::from(line);
                cb.auto_decrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(code.to_string(), t.output[i]);
            }
        }
    }
}

#[cfg(test)]
mod code {
    use crate::std_alloc::{fmt, Vec};

    #[derive(Debug, Copy, Clone)]
    pub struct Code(pub u32, pub u32);

    impl From<(u32, u32)> for Code {
        fn from(t: (u32, u32)) -> Self {
            Self(t.0, t.1)
        }
    }

    impl From<&str> for Code {
        fn from(s: &str) -> Self {
            let t: Vec<u32> = s.splitn(2, ' ').map(|v| u32::from_str_radix(v, 16).unwrap()).collect();
            Self(t[0], t[1])
        }
    }

    impl fmt::Display for Code {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:08X} {:08X}", self.0, self.1)
        }
    }
}
