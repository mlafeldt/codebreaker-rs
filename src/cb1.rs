// Encrypt and decrypt codes using CB v1 scheme

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

pub fn encrypt_code_mut(addr: &mut u32, val: &mut u32) {
    let code = encrypt_code(*addr, *val);
    *addr = code.0;
    *val = code.1;
}

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

    struct Test {
        decrypted: (u32, u32),
        encrypted: (u32, u32),
    }

    fn tests() -> Vec<Test> {
        vec![
            Test {
                decrypted: (0x0031789a, 0x00000063),
                encrypted: (0x0ac93a95, 0x00000063),
            },
            Test {
                decrypted: (0x1031a028, 0x0000ffff),
                encrypted: (0x1a613d30, 0x0000ffff),
            },
            Test {
                decrypted: (0x201f6024, 0x00000000),
                encrypted: (0x2a973dbd, 0x00000000),
            },
            Test {
                decrypted: (0x902db32c, 0x0c0baff1),
                encrypted: (0x9ad420d3, 0x180ddeda),
            },
            Test {
                decrypted: (0xa008060c, 0x08028007),
                encrypted: (0xaae071c0, 0xaca684dd),
            },
            Test {
                decrypted: (0xbeefc0de, 0x00000000),
                encrypted: (0xb4336fa9, 0x4dfefb79),
            },
        ]
    }

    #[test]
    fn test_encrypt_code() {
        for t in tests().iter() {
            let result = encrypt_code(t.decrypted.0, t.decrypted.1);
            assert_eq!(t.encrypted, result);
        }
    }

    #[test]
    fn test_encrypt_code_mut() {
        for t in tests().iter() {
            let mut code = t.decrypted;
            encrypt_code_mut(&mut code.0, &mut code.1);
            assert_eq!(t.encrypted, code);
        }
    }

    #[test]
    fn test_decrypt_code() {
        for t in tests().iter() {
            let result = decrypt_code(t.encrypted.0, t.encrypted.1);
            assert_eq!(t.decrypted, result);
        }
    }

    #[test]
    fn test_decrypt_code_mut() {
        for t in tests().iter() {
            let mut code = t.encrypted;
            decrypt_code_mut(&mut code.0, &mut code.1);
            assert_eq!(t.decrypted, code);
        }
    }
}
