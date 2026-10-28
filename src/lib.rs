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
//!
//! # Platform support
//!
//! This crate is `no_std` and currently supports little-endian targets only.
//! The CB v7 implementation intentionally preserves byte-level behavior from
//! the original C code.

#![deny(clippy::all, clippy::nursery)]
#![deny(nonstandard_style, rust_2018_idioms)]
#![deny(missing_docs, missing_debug_implementations)]
#![forbid(unsafe_code)]
#![no_std]

// Unit tests use Vec and vec!, but no_std keeps std out of scope unless we
// reintroduce it explicitly for test builds.
#[cfg(test)]
extern crate std;

#[cfg(doctest)]
doc_comment::doctest!("../README.md", readme);

pub mod cb1;
pub mod cb7;
mod rc4;

use cb7::{Cb7, is_beefcode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Raw,
    V1,
    V7,
}

/// A processor for CB v1 and v7 codes.
#[derive(Debug, Clone)]
pub struct Codebreaker {
    // Explicit encrypt/decrypt calls use this as a Raw/V7 toggle. Auto-decrypt
    // also uses V1 while following detected CB v1-encrypted blocks.
    scheme: Scheme,

    // CB v7 cipher state, activated by new_v7 or after a beefcode transition.
    cb7: Cb7,

    // Remaining continuation lines in the current auto-decrypt block. Plain
    // encrypt/decrypt ignores this field.
    code_lines: usize,

    // Auto-decrypt: decrypted lines until CB v7 comes back on after
    // "FFFFFFFF 0000nnnn". 0 means never.
    v7_lines: u16,
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
            v7_lines: 0,
        }
    }

    /// Returns a new processor for all CB v7 codes published on CMGSCCC.com.
    ///
    /// Lets you omit `B4336FA9 4DFEFB79` as the first code in the list.
    pub fn new_v7() -> Self {
        // Same state as after auto-decrypting B4336FA9 4DFEFB79, where the
        // next line can't be an option line
        Self {
            scheme: Scheme::V7,
            cb7: Cb7::default(),
            code_lines: 1,
            v7_lines: 0,
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
            self.enter_v7(oldaddr, oldval);
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
            self.enter_v7(*addr, *val);
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
    ///
    /// Like CodeBreaker, it also follows `FFFFFFFF 0000nnnn`, which turns CB v7
    /// off for the next nnnn decrypted lines, or for good if nnnn is 0. That's
    /// how raw and CB v1 codes can follow CB v7 codes in the same list.
    pub fn auto_decrypt_code_mut(&mut self, addr: &mut u32, val: &mut u32) {
        match self.scheme {
            Scheme::V7 => self.auto_decrypt_v7(addr, val),
            Scheme::Raw | Scheme::V1 => self.auto_decrypt_v1_or_raw(addr, val),
        }
    }

    fn auto_decrypt_v1_or_raw(&mut self, addr: &mut u32, val: &mut u32) {
        if self.code_lines == 0 {
            // Like CodeBreaker, count lines before decryption. CB v1 encryption
            // can flip bit 22 of cmd 3, so this may differ from the plaintext.
            self.code_lines = num_code_lines(*addr) - 1;
            if (*addr >> 24) & 0x0e != 0 {
                if is_beefcode(*addr) {
                    // Like CodeBreaker, ignore a raw beefcode and pass the
                    // next two lines through unchanged
                    self.scheme = Scheme::Raw;
                    self.code_lines = 2;
                    return;
                }
                self.scheme = Scheme::V1;
                cb1::decrypt_code_mut(addr, val);
            } else {
                self.scheme = Scheme::Raw;
                return;
            }
        } else {
            self.code_lines -= 1;
            if self.scheme == Scheme::Raw {
                return;
            }
            cb1::decrypt_code_mut(addr, val);
        }

        self.count_v7_line();
        if is_beefcode(*addr) {
            self.enter_v7(*addr, *val);
            self.code_lines = 1;
        }
    }

    fn auto_decrypt_v7(&mut self, addr: &mut u32, val: &mut u32) {
        self.cb7.decrypt_code_mut(addr, val);
        if self.code_lines == 0 {
            self.code_lines = num_code_lines(*addr);
            if self.code_lines == 1 && *addr == 0xffff_ffff {
                // CodeBreaker reads "FFFFFFFF 000Xnnnn" at the start of a CB v7
                // code as options for the next lines:
                //
                // - X & 1: If set, CB v7 stays on. Otherwise, raw and CB v1
                //   codes are detected again, and the next beefcode starts over
                //   with the default key and seeds.
                // - X & 2: The next code is decrypted with CB v7 even if it's
                //   off, and unless it's a beefcode, it becomes the key:
                //   [a ^ k0, v ^ k1, a - k2, v + k3, (a - v) ^ k4], where k is
                //   the key as of the last beefcode. The multiplications keep
                //   using k.
                // - nnnn: If not 0, the previous mode returns after nnnn more
                //   decrypted lines, not counting raw lines and the new key.
                //
                // CB2crypt documented "FFFFFFFF 00000000" as the way to add
                // raw codes after CB v7 codes, so we support X & 1 and nnnn.
                // We ignore X & 2: no code list is known to use it, and it
                // would take a lot more state.
                if *val & 0x0001_0000 == 0 {
                    // Back to detecting raw and CB v1 codes
                    self.scheme = Scheme::V1;
                }
                self.v7_lines = *val as u16;
                self.code_lines = 0;
                return;
            }
        }
        self.code_lines -= 1;

        self.count_v7_line();
        if is_beefcode(*addr) {
            self.enter_v7(*addr, *val);
            self.code_lines = 1;
        }
    }

    // Like CodeBreaker, count decrypted lines (CB v1 or v7) towards turning
    // CB v7 back on
    const fn count_v7_line(&mut self) {
        if self.v7_lines != 0 {
            self.v7_lines -= 1;
            if self.v7_lines == 0 {
                self.scheme = Scheme::V7;
            }
        }
    }

    // In V7 mode, Cb7 has already applied the beefcode at this point.
    // CodeBreaker v9.2 applies it a second time, and so do we. Outside of V7
    // mode, it starts over with the default key and seeds.
    fn enter_v7(&mut self, addr: u32, val: u32) {
        if self.scheme != Scheme::V7 {
            self.cb7 = Cb7::new();
        }
        self.cb7.beefcode(addr, val);
        self.scheme = Scheme::V7;
    }
}

const fn num_code_lines(addr: u32) -> usize {
    match addr >> 28 {
        3 if addr & 0x0040_0000 != 0 => 2,
        4..=6 => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::Code;
    use pretty_assertions::assert_eq;
    use std::{vec, vec::Vec};

    struct Test {
        cb: Codebreaker,
        decrypted: Vec<Code>,
        encrypted: Vec<Code>,
    }

    fn tests() -> Vec<Test> {
        vec![
            Test {
                cb: Codebreaker::new(),
                decrypted: vec![
                    "2043AFCC 2411FFFF".into(),
                    "BEEFC0DE 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
                encrypted: vec![
                    "2AFF014C 2411FFFF".into(),
                    "B4336FA9 4DFEFB79".into(),
                    "973E0B2A A7D4AF10".into(),
                ],
            },
            Test {
                cb: Codebreaker::new_v7(),
                decrypted: vec![
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
                encrypted: vec![
                    "D08F3A49 00078A53".into(),
                    "3818DDE5 E72B2B16".into(),
                    "973E0B2A A7D4AF10".into(),
                ],
            },
            Test {
                cb: Codebreaker::new_v7(),
                decrypted: vec![
                    "BEEFC0DE 00000000".into(),
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
                encrypted: vec![
                    "8787C575 1AC4C1B4".into(),
                    "02210430 184C16E8".into(),
                    "32E2A916 7E6017BA".into(),
                    "CBB720FD D61505E0".into(),
                ],
            },
            Test {
                cb: Codebreaker::new(),
                decrypted: vec![
                    "BEEFC0DE 00000000".into(),
                    "BEEFC0DF B16B00B5".into(),
                    "01234567 89ABCDEF".into(),
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
                encrypted: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "FE8B8601 C7C6F6CE".into(),
                    "2195D855 63FA11A7".into(),
                    "0CA31760 A6F7E88A".into(),
                    "679DC392 FA43E30B".into(),
                    "1CD9CCC3 6AF74E36".into(),
                ],
            },
            Test {
                cb: Codebreaker::new(),
                decrypted: vec![
                    "BEEFC0DE 00000000".into(),
                    "BEEFC0DF 00000000".into(),
                    "BEEFC0DE 12345678".into(),
                    "01234567 89ABCDEF".into(),
                    "9029BEAC 0C0A9225".into(),
                ],
                encrypted: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "EF3A41A5 8F460BA4".into(),
                    "3B070C70 52BA8DBD".into(),
                    "00DDD0A3 3EE4EC6F".into(),
                    "3B91B1FA 3D12C0B1".into(),
                ],
            },
            Test {
                cb: Codebreaker::default(),
                decrypted: vec![
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
                encrypted: vec![
                    "9A545CC6 188CBCFB".into(),
                    "2A973DBD 00000000".into(),
                    "2A03B60A 000000BE".into(),
                ],
            },
        ]
    }

    #[test]
    fn test_encrypt_code() {
        for t in &mut tests() {
            for (i, &code) in t.decrypted.iter().enumerate() {
                let result: Code = t.cb.encrypt_code(code.0, code.1).into();
                assert_eq!(result, t.encrypted[i]);
            }
        }
    }

    #[test]
    fn test_encrypt_code_mut() {
        for t in &mut tests() {
            for (i, code) in t.decrypted.iter_mut().enumerate() {
                t.cb.encrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(*code, t.encrypted[i]);
            }
        }
    }

    #[test]
    fn test_decrypt_code() {
        for t in &mut tests() {
            for (i, &code) in t.encrypted.iter().enumerate() {
                let result: Code = t.cb.decrypt_code(code.0, code.1).into();
                assert_eq!(result, t.decrypted[i]);
            }
        }
    }

    #[test]
    fn test_decrypt_code_mut() {
        for t in &mut tests() {
            for (i, code) in t.encrypted.iter_mut().enumerate() {
                t.cb.decrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(*code, t.decrypted[i]);
            }
        }
    }

    struct AutoTest {
        input: Vec<Code>,
        output: Vec<Code>,
    }

    fn auto_tests() -> Vec<AutoTest> {
        vec![
            AutoTest {
                // raw
                input: vec![
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
                output: vec![
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
            },
            AutoTest {
                // v1 encrypted
                input: vec![
                    "9A545CC6 188CBCFB".into(),
                    "2A973DBD 00000000".into(),
                    "2A03B60A 000000BE".into(),
                ],
                output: vec![
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
            },
            AutoTest {
                // v7 encrypted
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "D08F3A49 00078A53".into(),
                    "3818DDE5 E72B2B16".into(),
                    "973E0B2A A7D4AF10".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
            },
            AutoTest {
                // v7 encrypted, re-keyed with v7-encrypted BEEFC0DF
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "FE8B8601 C7C6F6CE".into(),
                    "2195D855 63FA11A7".into(),
                    "0CA31760 A6F7E88A".into(),
                    "679DC392 FA43E30B".into(),
                    "1CD9CCC3 6AF74E36".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "BEEFC0DF B16B00B5".into(),
                    "01234567 89ABCDEF".into(),
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
            },
            AutoTest {
                // v1 and v7 encrypted
                input: vec![
                    "9A545CC6 188CBCFB".into(),
                    "2A973DBD 00000000".into(),
                    "B4336FA9 4DFEFB79".into(),
                    "973E0B2A A7D4AF10".into(),
                ],
                output: vec![
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "BEEFC0DE 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
            },
            AutoTest {
                // v1-encrypted cmd 3 with bit 22 set only in the encrypted
                // address, so the next line belongs to it and gets decrypted
                input: vec!["3A550D56 9267D8DE".into(), "0029BEAC 0C0A9225".into()],
                output: vec!["30000035 12345678".into(), "0AADA1F9 0C0A9225".into()],
            },
            AutoTest {
                // raw beefcode, two raw lines, then v1 encrypted
                input: vec![
                    "BEEFC0DE 00000000".into(),
                    "2A973DBD 00000000".into(),
                    "2A03B60A 000000BE".into(),
                    "2A973DBD 00000000".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "2A973DBD 00000000".into(),
                    "2A03B60A 000000BE".into(),
                    "201F6024 00000000".into(),
                ],
            },
            AutoTest {
                // raw, v1, and v7 encrypted
                input: vec![
                    "9029BEAC 0C0A9225".into(),
                    "2A973DBD 00000000".into(),
                    "B4336FA9 4DFEFB79".into(),
                    "973E0B2A A7D4AF10".into(),
                ],
                output: vec![
                    "9029BEAC 0C0A9225".into(),
                    "201F6024 00000000".into(),
                    "BEEFC0DE 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
            },
            AutoTest {
                // FFFFFFFF 00000002: v7 off for two decrypted lines (the raw one
                // in between doesn't count)
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "D08F3A49 00078A53".into(),
                    "5B5DF76F E5E4BDCE".into(),
                    "2AFF014C 2411FFFF".into(),
                    "0031789A 00000063".into(),
                    "2A973DBD 00000000".into(),
                    "973E0B2A A7D4AF10".into(),
                    "D08F3A49 00078A53".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "9029BEAC 0C0A9225".into(),
                    "FFFFFFFF 00000002".into(),
                    "2043AFCC 2411FFFF".into(),
                    "0031789A 00000063".into(),
                    "201F6024 00000000".into(),
                    "2096F5B8 000000BE".into(),
                    "9029BEAC 0C0A9225".into(),
                ],
            },
            AutoTest {
                // FFFFFFFF 00000000: v7 off for good, then a beefcode starts over
                // with the default key
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "FE8B8601 C7C6F6CE".into(),
                    "2195D855 63FA11A7".into(),
                    "70B21EC6 D6A6D277".into(),
                    "2AFF014C 2411FFFF".into(),
                    "B4336FA9 4DFEFB79".into(),
                    "973E0B2A A7D4AF10".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "BEEFC0DF B16B00B5".into(),
                    "01234567 89ABCDEF".into(),
                    "FFFFFFFF 00000000".into(),
                    "2043AFCC 2411FFFF".into(),
                    "BEEFC0DE 00000000".into(),
                    "2096F5B8 000000BE".into(),
                ],
            },
            AutoTest {
                // FFFFFFFF 00000000 to add a raw code after v7 codes, as documented
                // by CB2crypt
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "410C34B6 663C5B57".into(),
                    "1C4D0A53 7FE27DE4".into(),
                    "C81AC878 32FCD351".into(),
                    "0CF49BDF A4E29C32".into(),
                    "204D98B0 3F800000".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "000FFFFE 0000015A".into(),
                    "000FFFFF 0000015A".into(),
                    "903DD9F8 00832021".into(),
                    "FFFFFFFF 00000000".into(),
                    "204D98B0 3F800000".into(),
                ],
            },
            AutoTest {
                // FFFFFFFF right after a beefcode isn't an option
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "1C65C412 26F27361".into(),
                    "397951B0 41569FE0".into(),
                    "3818DDE5 E72B2B16".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "FFFFFFFF 00000001".into(),
                    "2043AFCC 2411FFFF".into(),
                    "201F6024 00000000".into(),
                ],
            },
            AutoTest {
                // FFFFFFFF as the 2nd line of a code isn't an option
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "D08F3A49 00078A53".into(),
                    "460BA690 21E337B9".into(),
                    "1C65C412 26F27361".into(),
                    "397951B0 41569FE0".into(),
                    "3818DDE5 E72B2B16".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "9029BEAC 0C0A9225".into(),
                    "4043AFCC 00020001".into(),
                    "FFFFFFFF 00000001".into(),
                    "2043AFCC 2411FFFF".into(),
                    "201F6024 00000000".into(),
                ],
            },
            AutoTest {
                // The line after a beefcode is a continuation even if it starts a
                // 2-line code, so the 2nd line of that code can be an option
                input: vec![
                    "B4336FA9 4DFEFB79".into(),
                    "460BA690 21E337B9".into(),
                    "1C65C412 26F27361".into(),
                    "2AFF014C 2411FFFF".into(),
                    "3818DDE5 E72B2B16".into(),
                ],
                output: vec![
                    "BEEFC0DE 00000000".into(),
                    "4043AFCC 00020001".into(),
                    "FFFFFFFF 00000001".into(),
                    "2043AFCC 2411FFFF".into(),
                    "201F6024 00000000".into(),
                ],
            },
        ]
    }

    #[test]
    fn test_auto_decrypt_code() {
        for t in &mut auto_tests() {
            let mut cb = Codebreaker::new();
            for (i, &code) in t.input.iter().enumerate() {
                let result: Code = cb.auto_decrypt_code(code.0, code.1).into();
                assert_eq!(result, t.output[i]);
            }
        }
    }

    #[test]
    fn test_auto_decrypt_code_mut() {
        for t in &mut auto_tests() {
            let mut cb = Codebreaker::new();
            for (i, code) in t.input.iter_mut().enumerate() {
                cb.auto_decrypt_code_mut(&mut code.0, &mut code.1);
                assert_eq!(*code, t.output[i]);
            }
        }
    }

    #[test]
    fn test_auto_decrypt_code_new_v7() {
        // Same as starting with B4336FA9 4DFEFB79
        let first = Code::from("B4336FA9 4DFEFB79");
        for t in auto_tests().iter().filter(|t| t.input[0] == first) {
            let mut cb = Codebreaker::new_v7();
            for (i, &code) in t.input.iter().enumerate().skip(1) {
                let result: Code = cb.auto_decrypt_code(code.0, code.1).into();
                assert_eq!(result, t.output[i]);
            }
        }
    }
}

#[cfg(test)]
mod code {
    use core::fmt;
    use std::vec::Vec;

    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct Code(pub u32, pub u32);

    impl From<(u32, u32)> for Code {
        fn from(t: (u32, u32)) -> Self {
            Self(t.0, t.1)
        }
    }

    impl From<&str> for Code {
        fn from(s: &str) -> Self {
            let t: Vec<u32> = s
                .splitn(2, ' ')
                .map(|v| u32::from_str_radix(v, 16).expect("invalid code format"))
                .collect();

            Self(t[0], t[1])
        }
    }

    // Implements ToString
    impl fmt::Display for Code {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:08X} {:08X}", self.0, self.1)
        }
    }

    // Used by assert_eq!
    impl fmt::Debug for Code {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{self}")
        }
    }
}
