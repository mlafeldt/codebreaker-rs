# Zig Port of codebreaker-rs

This is a pure idiomatic Zig port of the CodeBreaker PS2 cheat code encryption/decryption library.

## Implementation Details

The Zig implementation successfully ports all functionality from the Rust version:

### Modules

- **`src/rc4.zig`** - RC4 stream cipher implementation
- **`src/cb1.zig`** - CodeBreaker v1-v6 encryption/decryption
- **`src/cb7.zig`** - CodeBreaker v7+ encryption/decryption with RSA
- **`src/codebreaker.zig`** - Main library interface combining CB1 and CB7

### Key Features

- ✅ Pure Zig implementation (no external dependencies)
- ✅ All original tests passing (19/19 tests)
- ✅ RSA encryption using native u128 arithmetic (no BigInt library needed)
- ✅ Idiomatic Zig code with proper error handling
- ✅ Works with Zig 0.15.1+

### RSA Implementation

The biggest challenge was handling RSA modular exponentiation without a mature BigInt library. The solution uses:

- **u128 arithmetic** for intermediate calculations in modular multiplication
- **Square-and-multiply algorithm** for efficient modular exponentiation
- Since all values are u64, u128 provides sufficient precision for (a * b) mod m operations

### Build & Test

```bash
# Run tests
zig build test

# Build static library
zig build

# Library will be in zig-out/lib/libcodebreaker.a
```

### Usage Example

```zig
const codebreaker = @import("codebreaker");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cb = codebreaker.Codebreaker.init(allocator);

    const decrypted = try cb.decryptCode(0x2AFF014C, 0x2411FFFF);
    // decrypted = (0x2043AFCC, 0x2411FFFF)
}
```

## Comparison with Rust Version

| Aspect | Rust | Zig |
|--------|------|-----|
| Lines of code | ~537 | ~1151 (includes more tests) |
| Dependencies | num-bigint, bytemuck | None (stdlib only) |
| no_std support | Yes | N/A (different paradigm) |
| Test framework | Built-in | Built-in |
| Build system | Cargo | Zig build |
| RSA implementation | num-bigint | u128 modular arithmetic |

## Performance

The Zig implementation uses u128 arithmetic for RSA operations, which is more efficient than BigInt for the specific u64 values used in CodeBreaker encryption.

## Lessons Learned

1. **Zig 0.15 API changes**: The build system and BigInt APIs changed significantly in Zig 0.15
2. **u128 is sufficient**: For u64 modular arithmetic, u128 intermediate values avoid BigInt complexity
3. **Operator precedence**: Zig's operator precedence required explicit parentheses in some cases
4. **Memory management**: Zig's allocator pattern is explicit but flexible

## License

Same as original: MIT OR Apache-2.0
