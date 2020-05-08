// Implementation of the stream cipher RC4
// Based on https://github.com/DaGenix/rust-crypto/blob/master/src/rc4.rs

#[derive(Copy, Clone)]
pub struct Rc4 {
    i: u8,
    j: u8,
    state: [u8; 256],
}

impl Rc4 {
    #[allow(clippy::needless_range_loop)]
    pub fn new(key: &[u8]) -> Rc4 {
        assert!(!key.is_empty() && key.len() <= 256);
        let mut state = [0; 256];
        for i in 0..256 {
            state[i] = i as u8
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Rc4 { i: 0, j: 0, state }
    }

    pub fn crypt(&mut self, buf: &mut [u8]) {
        for i in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let j = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
            *i ^= self.state[j as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Test {
        key: &'static str,
        input: &'static str,
        output: Vec<u8>,
    }

    #[rustfmt::skip]
    fn wikipedia_tests() -> Vec<Test> {
        vec![
            Test {
                key: "Key",
                input: "Plaintext",
                output: vec![0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3],
            },
            Test {
                key: "Wiki",
                input: "pedia",
                output: vec![0x10, 0x21, 0xbf, 0x04, 0x20],
            },
            Test {
                key: "Secret",
                input: "Attack at dawn",
                output: vec![0x45, 0xa0, 0x1f, 0x64, 0x5f, 0xc3, 0x5b,
                             0x38, 0x35, 0x52, 0x54, 0x4b, 0x9b, 0xf5,
                ],
            },
        ]
    }

    #[test]
    fn test_crypt() {
        for t in wikipedia_tests().iter() {
            let mut rc4 = Rc4::new(t.key.as_bytes());
            let mut buf = t.input.as_bytes().to_vec();
            rc4.crypt(&mut buf);
            assert_eq!(t.output, buf);
        }
    }
}
