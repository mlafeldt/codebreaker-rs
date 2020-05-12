//! Encrypt and decrypt cheat codes for all versions of CodeBreaker PS2.
//!
//! Uses [cb1](cb1/index.html) and [cb7](cb7/index.html) under the hood to
//! support both CB v1 and v7 codes.
//!
//! # Quick Start
//!
//! ```
//! use codebreaker::Codebreaker;
//!
//! let mut encrypted: Vec<(u32, u32)> = vec![
//!     (0x2AFF014C, 0x2411FFFF),
//!     (0xB4336FA9, 0x4DFEFB79),
//!     (0x973E0B2A, 0xA7D4AF10),
//! ];
//! let decrypted: Vec<(u32, u32)> = vec![
//!     (0x2043AFCC, 0x2411FFFF),
//!     (0xBEEFC0DE, 0x00000000),
//!     (0x2096F5B8, 0x000000BE),
//! ];
//!
//! let mut cb = Codebreaker::new();
//! for code in encrypted.iter_mut() {
//!     cb.decrypt_code_mut(&mut code.0, &mut code.1);
//! }
//! assert_eq!(decrypted, encrypted);
//! ```

// I don't like to reformat CB codes, seed tables, etc. for Clippy
#![allow(clippy::unreadable_literal)]
// Enforce rustdoc
#![deny(missing_docs)]

pub mod cb1;
pub mod cb7;
mod rc4;

use cb7::{is_beefcode, Cb7};

#[derive(PartialEq)]
enum Scheme {
    RAW,
    V1,
    V7,
}

/// Represents the current state of the code processor.
pub struct Codebreaker {
    scheme: Scheme,
    cb7: Cb7,
    code_lines: usize,
}

/// Does the same as [new](#method.new).
impl Default for Codebreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl Codebreaker {
    /// Allows to encrypt and decrypt all CB v1 and v7 codes.
    pub fn new() -> Codebreaker {
        Codebreaker {
            scheme: Scheme::RAW,
            cb7: Cb7::new(),
            code_lines: 0,
        }
    }

    /// Allows to encrypt and decrypt any CB v7 code published on CMGSCCC.com.
    ///
    /// Lets you omit `B4336FA9 4DFEFB79` as the first code in the list.
    pub fn new_v7() -> Codebreaker {
        Codebreaker {
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
    /// assert_eq!((0x2AFF014C, 0x2411FFFF), code);
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
    /// assert_eq!((0x2AFF014C, 0x2411FFFF), code);
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
    ///     assert_eq!(decrypted[i], result);
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
    /// assert_eq!(decrypted, encrypted);
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

    /// Smart version of [decrypt_code](#method.decrypt_code) that detects if
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
    ///     assert_eq!(output[i], cb.auto_decrypt_code(code.0, code.1));
    /// }
    /// ```
    pub fn auto_decrypt_code(&mut self, addr: u32, val: u32) -> (u32, u32) {
        let mut code = (addr, val);
        self.auto_decrypt_code_mut(&mut code.0, &mut code.1);
        code
    }

    /// Smart version of [decrypt_code_mut](#method.decrypt_code_mut) that
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
                    self.scheme = Scheme::RAW;
                    self.code_lines -= 1;
                }
            } else {
                self.code_lines -= 1;
                if self.scheme == Scheme::RAW {
                    return;
                }
                cb1::decrypt_code_mut(addr, val);
            }
        } else {
            self.cb7.decrypt_code_mut(addr, val);
            if self.code_lines == 0 {
                self.code_lines = num_code_lines(*addr);
                if self.code_lines == 1 && *addr == 0xffffffff {
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

fn num_code_lines(addr: u32) -> usize {
    let cmd = addr >> 28;

    if cmd < 3 || cmd > 6 {
        1
    } else if cmd == 3 {
        if addr & 0x00400000 != 0 {
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

    struct Test {
        cb: Codebreaker,
        decrypted: Vec<&'static str>,
        encrypted: Vec<&'static str>,
    }

    #[rustfmt::skip]
    fn tests() -> Vec<Test> {
        vec![
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
            Test {
                cb: Codebreaker::new(),
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
        ]
    }

    #[test]
    fn test_encrypt_code() {
        for t in tests().iter_mut() {
            for (i, line) in t.decrypted.iter().enumerate() {
                let code = parse_code(line);
                let result = t.cb.encrypt_code(code.0, code.1);
                assert_eq!(t.encrypted[i], format_code(result));
            }
        }
    }

    #[test]
    fn test_encrypt_code_mut() {
        for t in tests().iter_mut() {
            for (i, line) in t.decrypted.iter().enumerate() {
                let mut code = parse_code(line);
                t.cb.encrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(t.encrypted[i], format_code(code));
            }
        }
    }

    #[test]
    fn test_decrypt_code() {
        for t in tests().iter_mut() {
            for (i, line) in t.encrypted.iter().enumerate() {
                let code = parse_code(line);
                let result = t.cb.decrypt_code(code.0, code.1);
                assert_eq!(t.decrypted[i], format_code(result));
            }
        }
    }

    #[test]
    fn test_decrypt_code_mut() {
        for t in tests().iter_mut() {
            for (i, line) in t.encrypted.iter().enumerate() {
                let mut code = parse_code(line);
                t.cb.decrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(t.decrypted[i], format_code(code));
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
            AutoTest {
                // v7 encrypted (non-default BEEFC0DE)
                input: vec![
                    "B4336FA9 6C48E037",
                    "E65B5422 B12543CF",
                    "D14F5E52 FE26C9ED",
                    "DD9BB6F0 F5DF87F7",
                ],
                output: vec![
                    "BEEFC0DE DEADFACE",
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
            },
            AutoTest {
                // v7 encrypted (BEEFC0DF)
                input: vec![
                    "B4326FA9 1F0AFA2C",
                    "862316AB C59C5FB1",
                    "06133B66 95444FF1",
                    "565FD08D 9154AFF4",
                    "4EF412FE D03E4E13",
                ],
                output: vec![
                    "BEEFC0DF B16B00B5",
                    "01234567 89ABCDEF",
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
            },
            AutoTest {
                // v7 encrypted (BEEFC0DE + BEEFC0DF)
                input: vec![
                    "B4336FA9 4DFEFB79",
                    "FE8B8601 C7C6F6CE",
                    "2195D855 63FA11A7",
                    "0CA31760 A6F7E88A",
                    "679DC392 FA43E30B",
                    "1CD9CCC3 6AF74E36",
                ],
                output: vec![
                    "BEEFC0DE 00000000",
                    "BEEFC0DF B16B00B5",
                    "01234567 89ABCDEF",
                    "9029BEAC 0C0A9225",
                    "201F6024 00000000",
                    "2096F5B8 000000BE",
                ],
            },
        ]
    }

    #[test]
    fn test_auto_decrypt_code() {
        for t in auto_tests().iter_mut() {
            let mut cb = Codebreaker::new();
            for (i, line) in t.input.iter().enumerate() {
                let code = parse_code(line);
                let result = cb.auto_decrypt_code(code.0, code.1);
                assert_eq!(t.output[i], format_code(result));
            }
        }
    }

    #[test]
    fn test_auto_decrypt_code_mut() {
        for t in auto_tests().iter_mut() {
            let mut cb = Codebreaker::new();
            for (i, line) in t.input.iter().enumerate() {
                let mut code = parse_code(line);
                cb.auto_decrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(t.output[i], format_code(code));
            }
        }
    }

    fn parse_code(line: &str) -> (u32, u32) {
        let code: Vec<u32> = line.split(' ').map(|v| u32::from_str_radix(v, 16).unwrap()).collect();
        (code[0], code[1])
    }

    fn format_code(code: (u32, u32)) -> String {
        format!("{:08X} {:08X}", code.0, code.1)
    }
}
