//! Auto-decrypts cb2util-style code lists with codebreaker 0.3.2, 0.4.0 and
//! the local crate, and reports per game how many lines differ.
//!
//! usage: cargo run -- <file>...

use std::io::BufRead;

#[derive(Default)]
struct Game {
    name: String,
    lines: usize,
    v7_beefcodes: usize,
    diff_032: usize,
    diff_040: usize,
}

impl Game {
    fn report(&self, path: &str) {
        if self.lines > 0 {
            println!(
                "{path}: {} lines={} v7_beefcodes={} differ_vs_0.3.2={} differ_vs_0.4.0={}",
                self.name, self.lines, self.v7_beefcodes, self.diff_032, self.diff_040
            );
        }
    }
}

fn main() {
    for path in std::env::args().skip(1) {
        let f = std::io::BufReader::new(std::fs::File::open(&path).unwrap());
        let (mut a, mut b, mut c) = (v032::Codebreaker::new(), v040::Codebreaker::new(), head::Codebreaker::new());
        let mut game = Game::default();

        for line in f.lines().map(Result::unwrap) {
            // A quoted line starts a new game, which resets the crypto state
            if line.starts_with('"') {
                game.report(&path);
                game = Game { name: line, ..Default::default() };
                (a, b, c) = (v032::Codebreaker::new(), v040::Codebreaker::new(), head::Codebreaker::new());
                continue;
            }
            let p: Vec<_> = line.split_whitespace().collect();
            if p.len() != 2 || p.iter().any(|s| s.len() != 8) {
                continue;
            }
            let (Ok(addr), Ok(val)) = (u32::from_str_radix(p[0], 16), u32::from_str_radix(p[1], 16)) else {
                continue;
            };

            // Codebreaker has no public scheme accessor, so peek at its Debug output
            let was_v7 = format!("{c:?}").contains("V7");
            let x = a.auto_decrypt_code(addr, val);
            let y = b.auto_decrypt_code(addr, val);
            let z = c.auto_decrypt_code(addr, val);

            game.lines += 1;
            game.v7_beefcodes += usize::from(was_v7 && z.0 & 0xffff_fffe == 0xbeef_c0de);
            game.diff_032 += usize::from(x != z);
            game.diff_040 += usize::from(y != z);
        }
        game.report(&path);
    }
}
