Reusable prompt for comparing this crate against a CodeBreaker PS2 binary.
Replace `<BINARY>` (and optionally narrow `<SCOPE>`) before use.

---

Goal: compare this crate's implementation (src/) against the CodeBreaker code
in <BINARY>, in both directions. Find every behavioral difference, however
small, and everything the binary does in <SCOPE, default: code
encryption/decryption> that the crate doesn't.

Ground rules:
- The binary is the reference. Other implementations (cb2util, Omniconvert,
  older crate versions) only matter for historical context.
- Read everything in research/ first, especially REVERSING.md: earlier
  analyses, the address/global map of binaries already reversed, tooling
  pitfalls, and open findings. Reuse it instead of redoing it, and don't
  re-report issues that git log shows were already fixed.
- Don't change src/ or commit. Report back first.

Method:
1. Identify the binary: version strings, hashes, packer, signs of
   modification (cracks, patches). Unpack it if needed and keep the unpacked
   image and raw tool output in research/elf/ (gitignored).
2. Locate the code-crypto routines. Don't rely on addresses from other
   versions; find them by constants instead: beefcode immediates
   (0xBEEFC0DE/0xBEEFC0DF), the seed tables and RC4 key from src/cb1.rs and
   src/cb7.rs, the RSA modulus. Verify every constant table against src/.
3. Forward comparison (src/ -> binary): for every function and branch in
   src/, find the counterpart and compare at instruction level: signedness,
   shifts, masks, byte order, loop bounds, overflow, early returns, and the
   order of state updates. Confirm with listings wherever the decompiler is
   unreliable (e.g. R5900 3-operand mult/multu, MMI and 64-bit ops).
4. State: map every field of Codebreaker and Cb7 to the binary's globals,
   including when each is initialized and reset.
5. Reverse sweep (binary -> src/): list every branch and every global that the
   code-crypto routines and their callees touch. Mark each implemented,
   missing, or out of scope. Specify each missing feature well enough that it
   could be implemented.
6. Differential test: emulate the binary's per-line decrypt entry point (after
   its reset routine) with Ghidra's EmulatorHelper or similar. Compare against
   Codebreaker::auto_decrypt_code on random lists and on edge cases:
   - every command nibble and line-count flag
   - beefcodes in every mode, with and without extra seed lines
   - encryption-option lines
   - RSA and multiplier boundary values
   Hook any instructions the emulator models incorrectly.
7. Coverage: record which basic blocks of the code-crypto functions the
   emulator executed. For each block never reached, construct an input that
   reaches it and compare again. Any block you can't reach is either missing
   from src/ or dead code; say which.
8. Encryption: the device only decrypts. Check that the crate's encrypt
   functions are the exact inverse of the emulated decrypt on every path.
9. Other crypto users: find every other caller of the crypto primitives (RC4,
   RSA, V1/V7 routines). Identify what each one protects (files, saves,
   network data) and whether it belongs in this crate.
10. If research/ already covers another version, diff the code-crypto
    routines between the versions and note any behavioral changes.

Output (append a new section to research/REVERSING.md, or a new file per
binary):
- Binary identity and how it was unpacked.
- One verdict per Rust function (identical or differs), with addresses and
  listing excerpts as evidence.
- A table of binary features: implemented, missing, or out of scope, with
  addresses.
- For each difference: concrete input, binary output (from emulation), crate
  output, and a proposed fix with a test vector.
- For each missing feature: a spec plus test vectors from emulation.
- Block coverage per function, and any unreached blocks.
- Version differences, if step 10 applied.
- Tooling notes and pitfalls worth recording for next time.
