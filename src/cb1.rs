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
pub const fn encrypt_code(mut addr: u32, mut val: u32) -> (u32, u32) {
    let cmd = (addr >> 28) as usize;
    let tmp = addr & 0xff00_0000;
    addr = ((addr & 0xff) << 16) | ((addr >> 8) & 0xffff);
    addr = (tmp | (addr.wrapping_add(SEEDS[1][cmd]) & 0x00ff_ffff)) ^ SEEDS[0][cmd];
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
pub const fn decrypt_code(mut addr: u32, mut val: u32) -> (u32, u32) {
    let cmd = (addr >> 28) as usize;
    if cmd > 2 {
        val = (addr ^ val).wrapping_sub(SEEDS[2][cmd]);
    }
    let tmp = addr ^ SEEDS[0][cmd];
    addr = tmp.wrapping_sub(SEEDS[1][cmd]);
    addr = (tmp & 0xff00_0000) | ((addr & 0xffff) << 8) | ((addr >> 16) & 0xff);
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
        0x0a0b_8d9b, 0x0a01_33f8, 0x0af7_33ec, 0x0a15_c574,
        0x0a50_ac20, 0x0a92_0fb9, 0x0a59_9f0b, 0x0a4a_a0e3,
        0x0a21_c012, 0x0a90_6254, 0x0a31_fd54, 0x0a09_1c0e,
        0x0a37_2b38, 0x0a6f_266c, 0x0a61_dd4a, 0x0a0d_bf92,
    ],
    [
        0x0028_8596, 0x0037_dd28, 0x003b_eef1, 0x000b_c822,
        0x00bc_935d, 0x00a1_39f2, 0x00e9_bbf8, 0x00f5_7f7b,
        0x0090_d704, 0x0018_14d4, 0x00c5_848e, 0x005b_83e7,
        0x0010_8cf7, 0x0046_ce5a, 0x003a_5bf4, 0x006f_affc,
    ],
    [
        0x1dd9_a10a, 0xb95a_b9b0, 0x5cf5_d328, 0x95fe_7f10,
        0x8e2d_6303, 0x16bb_6286, 0xe389_324c, 0x07ac_6ea8,
        0xaa48_11d8, 0x76ce_4e18, 0xfe44_7516, 0xf9cd_94d0,
        0x4c24_dedb, 0x6827_5c4e, 0x7249_4382, 0xc8aa_88e8,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code;
    use crate::std_alloc::Vec;

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
            let code = code::parse(t.decrypted);
            let result = encrypt_code(code.0, code.1);
            assert_eq!(t.encrypted, code::format(result));
        }
    }

    #[test]
    fn test_encrypt_code_mut() {
        for t in tests().iter() {
            let mut code = code::parse(t.decrypted);
            encrypt_code_mut(&mut code.0, &mut code.1);
            assert_eq!(t.encrypted, code::format(code));
        }
    }

    #[test]
    fn test_decrypt_code() {
        for t in tests().iter() {
            let code = code::parse(t.encrypted);
            let result = decrypt_code(code.0, code.1);
            assert_eq!(t.decrypted, code::format(result));
        }
    }

    #[test]
    fn test_decrypt_code_mut() {
        for t in tests().iter() {
            let mut code = code::parse(t.encrypted);
            decrypt_code_mut(&mut code.0, &mut code.1);
            assert_eq!(t.decrypted, code::format(code));
        }
    }
}
