//! Prints the cipher text of the two V7 re-key cases from issue #11 as
//! produced by codebreaker 0.3.2, 0.4.0 and the local crate.

fn main() {
    let cases: [(&str, &[(u32, u32)]); 2] = [
        (
            "common key + BEEFC0DE",
            &[(0xBEEFC0DE, 0), (0x9029BEAC, 0x0C0A9225), (0x201F6024, 0), (0x2096F5B8, 0xBE)],
        ),
        (
            "common key + BEEFC0DF (cb2util beef.enc test 8)",
            &[(0xBEEFC0DF, 0xB16B00B5), (0x01234567, 0x89ABCDEF), (0x9029BEAC, 0x0C0A9225)],
        ),
    ];
    for (name, codes) in cases {
        println!("{name}");
        let (mut a, mut b, mut c) = (v032::Codebreaker::new_v7(), v040::Codebreaker::new_v7(), head::Codebreaker::new_v7());
        for &(addr, val) in codes {
            let (x, y, z) = (a.encrypt_code(addr, val), b.encrypt_code(addr, val), c.encrypt_code(addr, val));
            println!(
                "  {addr:08X} {val:08X}  0.3.2: {:08X} {:08X}  0.4.0: {:08X} {:08X}  head: {:08X} {:08X}",
                x.0, x.1, y.0, y.1, z.0, z.1
            );
        }
    }
}
