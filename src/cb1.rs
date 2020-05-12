//! Encrypt and decrypt cheat codes for CodeBreaker PS2 v1 - v6.

/// Encrypts a code and returns the result.
///
/// # Example
/// ```
/// use codebreaker::cb1;
///
/// let code = cb1::encrypt_code(0x1023CED8, 0x000003E7);
/// assert_eq!((0x1A11330E, 0x000003E7), code);
/// ```
pub fn encrypt_code(mut addr: u32, mut val: u32) -> (u32, u32) {
    let cmd = (addr >> 28) as usize;
    let tmp = addr & 0xff000000;
    addr = ((addr & 0xff) << 16) | ((addr >> 8) & 0xffff);
    addr = (tmp | (addr.wrapping_add(SEEDS[1][cmd]) & 0x00ffffff)) ^ SEEDS[0][cmd];
    if cmd > 2 {
        val = addr ^ val.wrapping_add(SEEDS[2][cmd]);
    }
    (addr, val)
}

/// Encrypts a code directly.
///
/// # Example
/// ```
/// use codebreaker::cb1;
///
/// let mut code = (0x1023CED8, 0x000003E7);
/// cb1::encrypt_code_mut(&mut code.0, &mut code.1);
/// assert_eq!((0x1A11330E, 0x000003E7), code);
/// ```
pub fn encrypt_code_mut(addr: &mut u32, val: &mut u32) {
    let code = encrypt_code(*addr, *val);
    *addr = code.0;
    *val = code.1;
}

/// Decrypts a code and returns the result.
///
/// # Example
/// ```
/// use codebreaker::cb1;
///
/// let code = cb1::decrypt_code(0x1A11330E, 0x000003E7);
/// assert_eq!((0x1023CED8, 0x000003E7), code);
/// ```
pub fn decrypt_code(mut addr: u32, mut val: u32) -> (u32, u32) {
    let cmd = (addr >> 28) as usize;
    if cmd > 2 {
        val = (addr ^ val).wrapping_sub(SEEDS[2][cmd]);
    }
    let tmp = addr ^ SEEDS[0][cmd];
    addr = tmp.wrapping_sub(SEEDS[1][cmd]);
    addr = (tmp & 0xff000000) | ((addr & 0xffff) << 8) | ((addr >> 16) & 0xff);
    (addr, val)
}

/// Decrypts a code directly.
///
/// # Example
/// ```
/// use codebreaker::cb1;
///
/// let mut code = (0x1A11330E, 0x000003E7);
/// cb1::decrypt_code_mut(&mut code.0, &mut code.1);
/// assert_eq!((0x1023CED8, 0x000003E7), code);
/// ```
pub fn decrypt_code_mut(addr: &mut u32, val: &mut u32) {
    let code = decrypt_code(*addr, *val);
    *addr = code.0;
    *val = code.1;
}

#[rustfmt::skip]
const SEEDS: [[u32; 16]; 3] = [
    [
        0x0a0b8d9b, 0x0a0133f8, 0x0af733ec, 0x0a15c574,
        0x0a50ac20, 0x0a920fb9, 0x0a599f0b, 0x0a4aa0e3,
        0x0a21c012, 0x0a906254, 0x0a31fd54, 0x0a091c0e,
        0x0a372b38, 0x0a6f266c, 0x0a61dd4a, 0x0a0dbf92,
    ],
    [
        0x00288596, 0x0037dd28, 0x003beef1, 0x000bc822,
        0x00bc935d, 0x00a139f2, 0x00e9bbf8, 0x00f57f7b,
        0x0090d704, 0x001814d4, 0x00c5848e, 0x005b83e7,
        0x00108cf7, 0x0046ce5a, 0x003a5bf4, 0x006faffc,
    ],
    [
        0x1dd9a10a, 0xb95ab9b0, 0x5cf5d328, 0x95fe7f10,
        0x8e2d6303, 0x16bb6286, 0xe389324c, 0x07ac6ea8,
        0xaa4811d8, 0x76ce4e18, 0xfe447516, 0xf9cd94d0,
        0x4c24dedb, 0x68275c4e, 0x72494382, 0xc8aa88e8,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{format_code, parse_code};

    struct Test {
        decrypted: &'static str,
        encrypted: &'static str,
    }

    fn tests() -> Vec<Test> {
        vec![
            Test {
                decrypted: "0031789A 00000063",
                encrypted: "0AC93A95 00000063",
            },
            Test {
                decrypted: "1031A028 0000FFFF",
                encrypted: "1A613D30 0000FFFF",
            },
            Test {
                decrypted: "201F6024 00000000",
                encrypted: "2A973DBD 00000000",
            },
            Test {
                decrypted: "902DB32C 0C0BAFF1",
                encrypted: "9AD420D3 180DDEDA",
            },
            Test {
                decrypted: "A008060C 08028007",
                encrypted: "AAE071C0 ACA684DD",
            },
            Test {
                decrypted: "BEEFC0DE 00000000",
                encrypted: "B4336FA9 4DFEFB79",
            },
        ]
    }

    #[test]
    fn test_encrypt_code() {
        for t in tests().iter() {
            let code = parse_code(t.decrypted);
            let result = encrypt_code(code.0, code.1);
            assert_eq!(t.encrypted, format_code(result));
        }
    }

    #[test]
    fn test_encrypt_code_mut() {
        for t in tests().iter() {
            let mut code = parse_code(t.decrypted);
            encrypt_code_mut(&mut code.0, &mut code.1);
            assert_eq!(t.encrypted, format_code(code));
        }
    }

    #[test]
    fn test_decrypt_code() {
        for t in tests().iter() {
            let code = parse_code(t.encrypted);
            let result = decrypt_code(code.0, code.1);
            assert_eq!(t.decrypted, format_code(result));
        }
    }

    #[test]
    fn test_decrypt_code_mut() {
        for t in tests().iter() {
            let mut code = parse_code(t.encrypted);
            decrypt_code_mut(&mut code.0, &mut code.1);
            assert_eq!(t.decrypted, format_code(code));
        }
    }
}
