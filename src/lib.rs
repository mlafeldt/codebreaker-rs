// I don't like to reformat CB codes, seed tables, etc. for Clippy
#![allow(clippy::unreadable_literal)]

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

pub struct Codebreaker {
    scheme: Scheme,
    cb7: Cb7,
    code_lines: usize,
}

impl Default for Codebreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl Codebreaker {
    pub fn new() -> Codebreaker {
        Codebreaker {
            scheme: Scheme::RAW,
            cb7: Cb7::new(),
            code_lines: 0,
        }
    }

    pub fn new_v7() -> Codebreaker {
        Codebreaker {
            scheme: Scheme::V7,
            cb7: Cb7::default(),
            code_lines: 0,
        }
    }

    // Used to encrypt a list of CB codes (V1 + V7)
    pub fn encrypt_code(&mut self, addr: u32, val: u32) -> (u32, u32) {
        let mut code = (addr, val);
        self.encrypt_code_mut(&mut code.0, &mut code.1);
        code
    }

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

    // Used to decrypt a list of CB codes (V1 + V7)
    pub fn decrypt_code(&mut self, addr: u32, val: u32) -> (u32, u32) {
        let mut code = (addr, val);
        self.decrypt_code_mut(&mut code.0, &mut code.1);
        code
    }

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

    // Smart version of decrypt_code() that detects if a code needs to be decrypted and how
    pub fn auto_decrypt_code(&mut self, addr: u32, val: u32) -> (u32, u32) {
        let mut code = (addr, val);
        self.auto_decrypt_code_mut(&mut code.0, &mut code.1);
        code
    }

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
