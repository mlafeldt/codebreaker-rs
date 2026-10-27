//! Runs the local crate on the lists that tools/ghidra/Emu.java emulates.
//!
//! usage: cargo run --example emucmp -- <auto|decrypt|encrypt> <lists.txt>
//!
//! auto:    auto_decrypt_code on every line, prints input, output and state
//!          in Emu.java's format (fields the crate lacks are left out)
//! decrypt: same with decrypt_code
//! encrypt: encrypt_code on every line, prints the cipher text as a new list
//!
//! Every list starts with Codebreaker::new(). Primitive calls ("!...") are
//! skipped.

use head::Codebreaker;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (cmd, path) = (args[1].as_str(), &args[2]);
    let mut cb = Codebreaker::new();
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some(name) = line.strip_prefix("===") {
            println!("=== {}", name.trim());
            cb = Codebreaker::new();
            continue;
        }
        let p: Vec<u32> = line.split_whitespace().map(|s| u32::from_str_radix(s, 16).unwrap()).collect();
        let (a, v) = (p[0], p[1]);
        let r = match cmd {
            "auto" => cb.auto_decrypt_code(a, v),
            "decrypt" => cb.decrypt_code(a, v),
            "encrypt" => cb.encrypt_code(a, v),
            _ => panic!("unknown command {cmd}"),
        };
        if cmd == "encrypt" {
            println!("{:08X} {:08X}", r.0, r.1);
        } else {
            println!("{a:08X} {v:08X} -> {:08X} {:08X} {}", r.0, r.1, state(&cb));
        }
    }
}

// Codebreaker has no state accessors, so parse its Debug output
fn state(cb: &Codebreaker) -> String {
    let d = format!("{cb:?}");
    let field = |name: &str| {
        let i = d.find(&format!("{name}: ")).unwrap() + name.len() + 2;
        let rest = &d[i..];
        let end = if rest.starts_with('[') { rest.find(']').unwrap() + 1 } else { rest.find([',', ' ', '}']).unwrap() };
        rest[..end].to_string()
    };
    let key: Vec<String> = field("key")
        .trim_matches(['[', ']'])
        .split(", ")
        .map(|k| format!("{:08X}", k.parse::<u32>().unwrap()))
        .collect();
    // main has a Scheme, ffffffff-encryption-options separate v7/v1 flags
    let scheme = if d.contains("scheme: ") {
        field("scheme")
    } else if field("v7") == "true" {
        "V7".into()
    } else if field("v1") == "true" {
        "V1".into()
    } else {
        "Raw".into()
    };
    format!(
        "scheme={} lines={:08X} bf={:X} init={:X} key={}",
        scheme,
        field("code_lines").parse::<u32>().unwrap(),
        u8::from(field("beefcodf") == "true"),
        u8::from(field("initialized") == "true"),
        key.join(",")
    )
}
