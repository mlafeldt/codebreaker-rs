# Review and follow-up of v9.2/v10 research

[Research index](REVERSING.md) · [v9.2](V9.md) · [v10](V10.md) · [Review and follow-up](REVIEW.md)

## 1. Review of all findings (2026-10-30)

This section preserves the review of `research/` and `src/` at `2e6c9d4`
(`research`). The review itself changed no implementation or existing research
tool. Its line references (including `REVERSING.md:N`) and quoted claims
below refer to that reviewed commit, not the corrected text now in
[v9.2](V9.md) and [v10](V10.md). Follow-up changes and remaining unknowns
are recorded in §1.5.
Supporting text, logs, source snapshots, and the new rekey probe are checked in
under `elf/review/`; the REA bundle is `elf/review-rea-v92.json`. Firmware ELF
and BIN images remain untracked.

The main v9.2 crypto findings hold up. The existing fixes are present, and the
two intentional departures remain the firmware RSA defect and option bit 17.
Fresh v10 emulation also supports the executable model. The largest correction
is to the disc-lock explanation: its supposedly inaccessible disc-key input is
exactly reproducible from the serial `SLUS-20202`. There are also real false
passes in the research comparison tools, an incorrect v10 option summary, and
several conclusions that exceed the evidence.

No new demonstrated defect in `src/` emerged from this review. That is a bounded
result, not a proof that every input or every CodeBreaker release is covered.

### 1.1 Findings

#### F1. The disc-lock narrative overstates both secrecy and hardware dependence

**High priority; exact reconstruction plus an unsupported hardware claim.**
Locations: `docs/disc-lock.html:243–255,342–351`; `REVERSING.md:1174–1213`;
related comments at `tools/cbv10_unpack.py:5–11`.

The visual explanation says only a genuine authenticated disc can return the
right input, calls it unavailable from the readable filesystem, and says the
FPU contribution cannot be emulated. Those statements do not follow from the
observed loader.

Fresh payload decompilation shows `0x1310f8` requesting a read-key reply with
arguments `(0, 0, 0x4b)`, then decoding and checking `SLUS` and decimal `20202`.
Applying the serial-based calculation in
[PCSX2's `cdvdReadKey`, revision `33127ad0`](https://github.com/PCSX2/pcsx2/blob/33127ad0df121e5b831494c389068ed9f9f3ad4b/pcsx2/CDVD/CDVD.cpp#L583-L620)
to `SLUS-20202` gives:

```text
key16 = 9369953955000000000000000000bc05
reply = 010000009369953955000000000000000000bc05
words = {1, 0x39956993, 0x55, 0, 0x05bc0000}
```

These are exactly the stub's `const20` words. The leading word is a status
value; the remaining 16 bytes are the read-key result. Thus the concrete input
used by the key schedule is reproducible in software, rather than an
inaccessible physical secret. This source comparison does not establish how
the original console authenticates optical media or whether an unmodified
loader boots a particular copy.

The FPU claim has a separate evidence gap. Reproducing arithmetic results does
not require demonstrated cycle accuracy. The unmodified mixer has not been
executed or independently reproduced here; its software reproducibility is
unresolved. Also, a value described as identical on every PS2 is a dependency
on hardware semantics, not evidence of binding to a particular console.

**Report correction:** describe the schedule as depending on an EE arithmetic
result and a read-key reply. Keep the hardcoded-input crack and successful
offline unpack as observations. Remove the claims of an uncopiable secret and
impossible emulation until independently established.

Evidence: `elf/review/disc/serial-reproduction.txt`, `disc/payload.log`,
`disc/payload2.log`, and the pinned primary source saved as `disc/PCSX2-CDVD.cpp`.

#### F2. The relocation normalizer can hide real changes and omit function tails

**High priority for the reliability of future comparisons; reproduced false pass.**
Locations: `tools/cbcrypt_diff.py:122–124,140–154`;
`REVERSING.md:1253–1255,1290–1294`.

Unlisted J/JAL targets normalize to `?`, and `rawmaskable()` accepts every
change to a J/JAL target field. Therefore the assertion that masking cannot
hide a real change is false. In a Python bytearray only, replacing the actual
v9.2 call at `0x13351c` from `jal 0x133428` to `jal 0x123450` still produces:

```text
mutated-bignum-call: v9.2 0x133220..0x134020 (896)
                    v10  0x1318e8..0x1326e8 (896)
  IDENTICAL modulo relocation
```

The same false pass occurs when v10's `0x131be4` call is changed from
`0x131af0` to `0x131af4`. No artifact was patched on disk.

Function boundaries have another weakness: `find_end()` stops at the first
`jr ra`. For memcpy it checks 43 words, although the span from memcpy to the
next memset entry contains 106 words and three returns. Conversely, v10 reset
tail-jumps to memset; the scanner runs past it into the following function.
The report's 36-instruction reset count includes padding and that function;
reset itself spans 33 instructions through `0x105328`.

**The actual bignum result survives independent verification.** Across the
complete 896-word core, every changed word is a correctly relocated call.
All 34 otherwise unlabelled internal calls map by `−0x1938`; external calls
map to the documented memcpy/memset/division counterparts. The complete
106-word memcpy span is also byte-identical. The tool's assurance is wrong,
even though those conclusions about these particular images remain supported.

**Report correction:** call the script a comparison aid. A trustworthy
equivalence check must retain unresolved target identity and validate function
extents and relocation mappings independently. No tool change was made.

Evidence: `elf/review/normalizer-probe.txt`, `v10/diff.txt`, `v10/ghidra.log`.

#### F3. Output comparison can silently overlook missing lines or return success on differences

**Medium priority; two concrete tool behaviors.**
Locations: `tools/cmpout.py:8–19`; `tools/emudiff.py:128–145`;
`tools/emudiff10.py:130–147`.

`cmpout.py` checks list names, but compares rows using `zip()` without checking
their lengths. A two-row list and a one-row list with the same first row yield:

```text
1 lists, 1 lines: 0 lists output differ, 0 state-only, 0 primitive differ
Exit status: 0
```

The missing row is ignored. Duplicate list names also overwrite prior entries
in its dictionary, so list-name uniqueness is another unstated precondition.

Separately, `emudiff.py` and `emudiff10.py` print mismatches but do not return a
failing status for them. The current crate versus the freshly emulated v9.2
`report` corpus prints five differing lists and exits with status 0. Those
five are expected intentional divergences; the issue is that a successful
shell command cannot establish agreement. These scripts do assert list and
row counts, unlike `cmpout.py`.

**Report correction:** inspect counters and row counts explicitly when citing
these tools. Their process exit status is not an equivalence verdict. The
fresh runs in this review were checked for both completeness and diagnostics.

Evidence: `elf/review/cmpout-truncation-probe.txt`; fresh v9.2 output at
`elf/review/v92/report.out`.

#### F4. The v10 summary incorrectly removes all options and omits a rekey change

**Medium priority; contradicted by fresh listings and emulation.**
Locations: `REVERSING.md:1312–1336`; compare
`tools/fwmodel10.py:43–47,109–121` and `tools/attrib.py:11–16`.

v10 still recognizes `FFFFFFFF`, stores the mode and counter, restores the
saved mode, records bit-17 option state, and has the key-from-line path. What
disappears is the forced-next-V7 condition and its `opt == 2` early return.
The retained logic is visible at `0x1051a8–0x1051f4` and
`0x105204–0x105228`. A fresh firmware vector demonstrates V7 switching off
and returning after one counted line:

```text
input                  v10 output             mode afterwards
B4336FA9 4DFEFB79 -> BEEFC0DE 00000000          00010000
CDCB1126 3ECCCE95 -> 01234567 89ABCDEF          00010000
1C65C412 26F27361 -> FFFFFFFF 00000001          01000001
0B842540 89ABCDEF -> 01234567 89ABCDEF          00010000
```

The rekey comparison also needs both paths. In addition to `rekey(1,val)`
ignoring `val`, v10's `rekey(0,val)` uses `(val + j) & 255` for byte index `j`
instead of byte `j` of `val`, and removes the zero-value seed-clearing case.
Instructions at `0x104a98` onward and the existing model agree. Direct fresh
firmware calls after the default beefcode produce:

```text
rekey(0,00000000): key=88D06E88,BB0542C6,4D6A1A95,84D61681,A26B2DEE
                  seeds CRC=C3CE4B1E
rekey(0,01020304): key=4D901190,2AB77E9F,38F22328,B7FFAD44,095B4DE2
                  seeds CRC=C5EBB321
```

The outer hard reset normally overwrites this intermediate rekey work, which
explains why the omission does not invalidate the main net-effect examples.
Finally, the misplaced fifth key word arms the extra-seed behavior only when
the word stored into `beefcodf` is nonzero; the prose should preserve that
condition rather than saying every such line necessarily arms it.

Evidence: `elf/review/v10/cases.txt`, `cases.out`, `ghidra.log`, `rekey.log`.

#### F5. Local path checks do not establish pristine retail provenance or patch attribution

**Medium priority; confidence and attribution error.**
Locations: `REVERSING.md:912–917,955–960,1057–1073,1157–1160,1233–1235`;
`docs/disc-lock.html:360–361,399–400`.

The supplied v10 loader is modified. Its extracted payload has the expected
version strings, a signature verdict that consumes `memcmp`, and intact
instructions at the three locations the loader later patches in RAM. These
are useful observations, but do not prove the entire payload is untouched
retail firmware. No clean reference image or independently authenticated
vendor digest was compared. The v9.2 N2E loader's stock provenance is likewise
not established merely by identifying its standard decompressor.

The CBC default-verdict difference is real: v9.2 `0x296080` contains 1, while
v10 `0x772c80` contains 0. It cannot distinguish a v9.2 modification from a
legitimate release change. Attribution to the Day1 server modification remains
a hypothesis. Similarly, comparison with another release identifies the
signature-verdict behavior difference, not the exact original bytes or full
scope of a historical author's patch.

**Report correction:** refer to the extracted v10 payload from the identified
modified loader. State which inspected paths differ or remain intact. Treat
whole-image authenticity and historical attribution as unresolved. The
artifact-to-artifact crypto comparison remains valid without retail provenance.

#### F6. The compatibility claim extends a finite corpus to all published codes

**Medium priority; unsupported generalization.**
Location: `REVERSING.md:1355–1387`.

The fixture result reproduces: 53 lists, 6,234 lines; only three synthetic
`beef.enc` lists differ, on 11 lines. This supports agreement on the remaining
50 lists. It does not establish that no distributed code ever used nonzero
beefcodes, repeated beefcodes, or bit-17 options, nor that every published
code matches both images.

There is a useful structural argument for a restricted path: with one
default beefcode and no later transition that exercises a differing path,
both images reach the same state and use the same primitives. State those
preconditions. A single default initial beefcode alone is insufficient if the
list later exercises differing option behavior. The crate's intentional RSA
and bit-17 departures also remain relevant to any blanket device-equivalence
claim.

**Report correction:** retain the fixture counts and demonstrated nonzero and
repeated-beefcode counterexamples. Replace universal historical claims with
the observed corpus boundary and conditional equivalence argument.

Evidence: `elf/review/v10/fixtures.txt`, `cases.txt`, `cases.out`.

#### F7. The second boot gate conflates distinct calls and an untraced failure outcome

**Medium priority; fresh binary evidence narrows the mechanism.**
Locations: `REVERSING.md:1111–1121,1195–1197,1227–1228`;
`docs/disc-lock.html:320–328,390–391`.

The three RAM writes are real, but the explanation groups different operations
into two proven disc-key checks ending in an immediate halt:

| Location | Observed operation |
|---|---|
| `jal` at `0x115b14` → `0x1310f8` | Obtains the read-key reply, checks decoded `SLUS`/`20202`, increments failure state at `0x9ea168` on mismatch, and opens `SYSTEM.CNF`. |
| Branch to `0x115b34` | Also skips a separate `0x131050` check, called at `0x115b30`. This check tests a byte of another RPC result against `0x20`. |
| `jal` at `0x1142c0` → `0x130e18` | Sends function 4 to custom RPC server `0xfa6a007e`. This caller does not test its return. Server-side meaning remains unresolved. |
| `0x114a50` | Marks error flags. This immediate handler does not itself halt. |

**Report correction:** describe the skipped serial/result checks and the
separate RPC call. A complete boot-failure claim requires following the IOP
service and subsequent error-state consumers. Static removal of those calls
does not prove either the clean boot outcome or the final failure behavior.

Evidence: `elf/review/disc/payload.log` and `payload2.log`.

#### F8. The RSA arithmetic finding does not prove signature unforgeability

**Medium priority; unsupported security conclusion.**
Location: `REVERSING.md:632–639`.

The two-limb, exponent-11 arithmetic defect is supported by listings, a model,
and firmware emulation. The signature verifier uses a different operand size,
modulus, exponent, and padding check. Those observations do not establish the
claims of no algebraic leverage or no search-space reduction, or that a
forgery necessarily needs the private key or a firmware patch. Merely ruling
out exponent 3 is not an analysis of that verifier's security.

**Report correction:** say no forgery was demonstrated and exploitability was
not established. This review does not claim an exploit exists. An intact
final comparison in v10 establishes that the result is consumed, not that the
entire signature scheme is sound.

### 1.2 Validation boundaries and smaller corrections

These affect how results should be read, rather than demonstrating another
crate defect:

- **“Identical state” has two meanings.** `emudiff.py:93–111` and the v10
  variant compare crate line count, effective scheme, and conditionally key
  and `beefcodf`. They do not compare crate seeds, `initialized`, or
  `lines_until_v7`. Model-versus-emulator checks compare every logged global
  and the seed CRC. Neither is a byte-for-byte comparison of all firmware
  memory. Keep these scopes separate in [v9.2 §9.1](V9.md#91-method) and subsequent summaries.
- **Block coverage is not exhaustive behavior coverage.** The listed [v9.2 §9.8](V9.md#98-coverage)
  totals reproduce, subject to Ghidra's incomplete EE decoding and function
  bodies. Hooks replace memcpy/memset; rare reduction paths are modeled but
  not all emulated. A block being reached once does not cover all values,
  edges, state histories, or overflow cases.
- **“The whole bad range” is not literal.** [v9.2 §9.4](V9.md#94-difference-the-firmwares-rsa-is-wrong-near-the-modulus-kept-105d376) describes 172,140 model
  checks including “the whole bad range.” The range contains roughly
  `2^31` values. The phrase needs a sampling or subrange definition. The
  defect's estimated frequency and missing-preimage rate are model estimates,
  not hardware measurements or exhaustive counts.
- **Some early prose is stale.** [v9.2 §6.3](V9.md#63-raw-beefcode-during-detection-fixed-in-d9bab13) describes the pre-fix raw-beefcode
  implementation in present tense; [v9.2 §6.6](V9.md#66-ffffffff-encryption-options-bit-16-and-count-in-src-since-16299e0-95) says `src/` otherwise ignores options
  despite implemented bit-16/count handling. The detailed later sections and
  current source are consistent about the fixes.
- **The patch is a full instruction-word change.** The signature-verdict
  comparison is `0x2c420001` versus `0x24020001`. The shorthand `2c→24`
  omits the changed source-register bits (`42→02`); changing only the opcode
  would not produce the documented unconditional `addiu v0,zero,1`.
- **The former reusable prompt contradicted branch policy.** At the reviewed
  commit, `COMPARE_PROMPT.md:19` said rebase, while `REVERSING.md:31–40` said
  merge and never rebase to preserve cited hashes. The prompt also forced
  unreached blocks into “missing or dead” at lines 52–54. A rare reachable
  path or an insufficient corpus is another possibility, already illustrated
  by [v9.2 §9.8](V9.md#98-coverage). The prompt has since been removed and its useful checklist folded
  into the [shared methodology](REVERSING.md#methodology-for-further-comparisons),
  with these rules corrected.

### 1.3 What remains supported

| Research area | Review result |
|---|---|
| [v9.2 §§1–2](V9.md#1-the-elf): v9.2 identity and unpack | Hashes match; a fresh N2E unpack is byte-identical to the saved ELF. Modified-image caveat remains necessary. |
| [v9.2 §§4–5](V9.md#4-map): maps and basic crypto | Constants, modulus, V1 transformation, line-count rule, RC4, inverse/multiplication, and v9.2 schedule remain supported. |
| [v9.2 §6.1](V9.md#61-beefcode-in-v7-mode-two-rekeys-matches-since-75471b6): double rekey | Firmware behavior and current fix remain supported. |
| [v9.2 §6.2](V9.md#62-v1-line-count-uses-the-encrypted-address-fixed-in-fadd9d9): encrypted-address V1 line count | Firmware ordering and current fix remain supported. |
| [v9.2 §6.3](V9.md#63-raw-beefcode-during-detection-fixed-in-d9bab13): raw beefcode continuation | Two following raw lines and the current fix remain supported; early explanatory prose is stale. |
| [v9.2 §§6.5–6.7](V9.md#65-key-copy): key copy, options, converter | Key copy and detailed v9.2 option specification remain supported. Converter behavior is outside this crate's interface and was not dynamically exercised in this review. |
| [v9.2 §7](V9.md#7-history): history and fixture comparison | Local fix history and finite corpus result are consistent. Author attribution and claims about all historical usage remain bounded. |
| [v9.2 §§8,9.9](V9.md#8-caveats): signature verdict and other crypto users | v9.2 forces success; v10 consumes the compare result at the inspected tail. File/loader callers remain outside code-line crypto; no end-to-end file import or payload execution was tested. |
| [v9.2 §9.3](V9.md#93-difference-encrypting-a-beefcode-as-beefc0dfs-extra-seed-line-fixed-in-23739ac): extra-seed encryption order | Current encryption reproduces all 120 saved plaintext-list ciphertexts and explicit decryption recovers all 2,270 lines. |
| [v9.2 §9.4](V9.md#94-difference-the-firmwares-rsa-is-wrong-near-the-modulus-kept-105d376): RSA defect | Confirmed behavior; current exact arithmetic deliberately differs. Signature exploitability and exact population rates remain unresolved. |
| [v9.2 §9.5](V9.md#95-ffffffff-encryption-options-bit-16-and-count-since-16299e0-bit-17-left-out): option bit 16/count and omitted bit 17 | Current source implements the former and intentionally omits the latter. Fresh report differences match that decision. |
| [v9.2 §§9.6–9.8](V9.md#96-state-map): state and coverage | Mapping and reported coverage totals remain useful, with the comparison and reachability boundaries above. |
| [v9.2 §9.10](V9.md#910-tooling-notes): tooling pitfalls | EE instruction hooks and private script/project isolation remain necessary. REA's current lane limitation was independently reproduced. |
| [v10 §§1.1–1.5,1.8](V10.md#11-provenance-and-image): v10 unpack and modifications | Fresh unpack reproduces the payload; hardcoded input stub, little-endian SHA-1 reconstruction, RC4/zlib recovery, and RAM patch words are supported. |
| [v10 §§1.6–1.10](V10.md#16-modified-loader-extracted-v10-payload): provenance and protection explanation | Intact inspected signature tail is supported; whole-image retail status and the broad disc/hardware boot narrative need F1, F5, and F7. |
| [v10 §§2.1–2.4](V10.md#21-method): version comparison | Same primitive core and four changed state functions are supported, with normalizer limitations and the corrected option/rekey semantics in F2/F4. |
| [v10 §2.5](V10.md#25-compatibility-on-the-checked-corpus): compatibility | Corpus result and counterexamples reproduce; universal published-code compatibility is unproven. |
| `docs/disc-lock.html` | Key equation and supplied-image constants remain useful; secrecy, impossibility, provenance, and boot-gate claims need the corrections above. |
| Comparison methodology and tools | The former prompt's checklist is consolidated in the [shared methodology](REVERSING.md#methodology-for-further-comparisons) with corrected branch and coverage guidance. Tool limitations F2/F3 still apply. |

### 1.4 Checks performed and evidence

| Check | Result |
|---|---|
| `cargo test --all-targets` | 19 passed. |
| `cargo test --doc` | 17 passed. |
| Fresh v9.2 Ghidra `report` run | 82 lines, 2,801,893 steps; byte-identical to the saved output. Current crate: four bit-17 list differences plus one RSA list difference; zero model mismatches. |
| Saved v9.2 targeted/model comparison | 3,221 lines; model agrees. Current crate: 40 output-difference lists explained by bit 17/RSA, plus two state-only option lists. |
| v9.2 `optfuzz16` | 3,378 lines, no crate output or selected-state differences. |
| Current explicit encryption/decryption | 120 plaintext lists / 2,270 lines reproduce saved fixed ciphertext and recover plaintext. |
| Fresh v10 Ghidra import/emulation | 46 lines, 1,305,718 instructions; zero output or logged-state mismatches against `fwmodel10.py`. |
| Direct v10 non-init rekey emulation | Both new vectors in F4 agree with the model. |
| cb2util model sweep | 53 lists / 6,234 lines; three synthetic lists / 11 lines differ. |
| Primitive-core raw comparison | Complete 896-word core verified with call mappings; complete 106-word memcpy span byte-identical. |
| Normalizer/output-comparator fault probes | False passes reproduced without changing source or on-disk binary bytes. |

Both packed image identities match the existing research:

```text
CBv92.ELF          3,292,756 bytes
d51a90c0d86fb33de52d80c5e1d7a372dc17c1e3d2a52645fff4922a573e4c83
CBv92.unpacked.elf 18,089,338 bytes
91c04ee76b1126b2b060298fe6c2d434740d2b1923f7e282bc154153c1b79edb
CBv10.BOOT.ELF     3,688,628 bytes
aafabd9b9ef8b74349ee6aa4272e4efa3fc1fd9838ceed78a23afff2521f3f04
CBv10.unpacked.bin 9,370,970 bytes
9cb83c7ffd28c09ebadf1bba986b34a4dce86bedb03ebb2023c4f944a5d422e3
```

REA with Ghidra 12.1.4 reproduced its v9.2 limitation: the profile pins
`MIPS:LE:32:default` and decompiling `0x1042b0` yields `halt_baddata()`.
Evidence ID:
`ev_f906ae3c970c29b02df39ab0812e61b6345eb2b4e7d9dac816e4b351d64b24e6`,
exported to `elf/review-rea-v92.json`. The v10 loader is rejected by the
selected provider as an unsupported machine-specific MIPS variant. Deep
inspection therefore used Ghidra headless with
`-processor MIPS:LE:64:64-32addr`, private script copies, and the existing EE
emulation hooks. The REA session was closed.

`elf/review/manifest.json` records the local evidence files and hashes. Fresh
firmware output is distinguished above from replay of stored corpora and
model-only fixture checks. No hardware or PCSX2 execution was performed. No
clean retail reference was acquired, no full IOP service investigation was
completed, and no signature-forgery analysis was performed. Those are explicit
remaining unknowns, not reasons to discard the narrower confirmed results.

### 1.5 Follow-up corrections (2026-10-30)

The findings above describe the reviewed snapshot. The affected explanations
in [v9.2](V9.md) and [v10](V10.md) have now been corrected in place, so readers need not reconstruct
current conclusions from a later warning alone. `main` was merged into
`research` in `9272a61`; this includes the public documentation corrections
and exact RSA boundary assertion (`0bb7c11`).

| Finding | Follow-up | Remaining boundary |
|---|---|---|
| F1: inaccessible inputs | [v10 §§1.5,1.8,1.10](V10.md#15-key-schedule-fun_01000248-solved) and the disc-lock page describe the status/read-key reply and its matching serial calculation. The FPU claim is narrowed to required arithmetic results. | Unmodified mixer reproduction and original-console optical authentication remain untested. |
| F2: masked changes and guessed ends | The normalizer retains unknown address identity, validates mapped coordinates, and uses verified explicit ranges. [v10 §2.1](V10.md#21-method) and the instruction counts in [v10 §2.2](V10.md#22-verdict) reflect this. | Static equality is not behavioral equivalence; unsupported mappings remain explicit. |
| F3: incomplete comparisons and status 0 | Comparison tools reject incomplete/duplicate input and distinguish agreement, differences, and invalid input. Reviewed differences require an exact input-bound baseline; model and plaintext failures cannot be waived. | Expected differences authorize only the recorded inputs and records, not a class of future failures. |
| F4: v10 option/rekey summary | [v10 §§2.3–2.5](V10.md#23-the-four-changed-functions) retain option recognition, describe the removed force/early-return paths and changed non-init derivation, and condition extra-seed behavior on a nonzero flag. | The model and checked vectors do not exhaust every possible state history. |
| F5: provenance and attribution | [v9.2 §§8–9](V9.md#8-caveats) and [v10 §1](V10.md#1-codebreaker-v10-loader-2026-10-28-corrected-2026-10-30) distinguish inspected paths from whole-image authenticity. The CBC default difference is recorded without claiming a located Day1 patch. | Retail provenance and historical attribution remain unestablished. |
| F6: universal compatibility | [v10 §2.5](V10.md#25-compatibility-on-the-checked-corpus) reports 50 matching game lists out of the 53-list, 6,234-line fixture corpus, with conditional equivalence and explicit counterexamples. | Usage outside that corpus and v7/v8 firmware behavior remain unknown. |
| F7: boot-gate conflation | [v10 §§1.8–1.10](V10.md#18-the-key-schedule-and-the-located-modifications) and the visual page separate serial/result checks from the custom function-4 RPC, and distinguish error flags from a halt. | IOP service meaning and final boot/failure outcomes remain unresolved. |
| F8: signature security assurance | [v9.2 §9.4](V9.md#94-difference-the-firmwares-rsa-is-wrong-near-the-modulus-kept-105d376) withdraws the unforgeability conclusion and limits the result to the demonstrated arithmetic defect. | No forgery was demonstrated and no full verifier security analysis was performed. |

The smaller corrections are also applied: [v9.2 §§5–6](V9.md#5-matched-primitives-and-schedule) identify the historical
pre-fix behavior, [v9.2 §9.1](V9.md#91-method) distinguishes selected crate state from logged model
state, [v9.2 §9.4](V9.md#94-difference-the-firmwares-rsa-is-wrong-near-the-modulus-kept-105d376) calls the bad-range checks samples rather than an exhaustive
sweep, and [v9.2 §8](V9.md#8-caveats) / [v10 §1.9](V10.md#19-spot-check-v10s-signature-verdict-is-intact) use the full differing instruction words. The standalone
comparison prompt was removed in `5c37fb7`; its corrected methodology is
retained in the [shared methodology](REVERSING.md#methodology-for-further-comparisons).

New tool regressions, comparison baselines, and verification outputs belong
under `elf/followup-2026-10-30/`. They are separate from the original
`elf/emu/` and `elf/review/` evidence, whose bytes and recorded identities are
preserved. A baseline records reviewed expected differences; generating one
is not itself evidence that a discrepancy is understood or acceptable.

The implementation commits are `93d03f1` (strict comparisons and exact
baselines), `281ee64` (validated relocation mappings and complete ranges),
`16530be` (selected-state records on every line), and `8259a17` (typed JSON
records, valid crate flags, and protection against hardlinked output targets).
`3c0735b` corrects the disc-lock page and model/unpacker comments. The 33
synthetic tool regressions pass without requiring any firmware images:

```
python3 -m unittest discover -s research/tools/tests -v
```

The follow-up replay uses the crate after merging `main`, and the original
firmware observations. It does not claim a new hardware or emulator run:

| Replay | Result | Evidence under `elf/followup-2026-10-30/` |
|---|---|---|
| v9.2 `report` | 13 lists, 82 lines; five lists with the known option/RSA output differences; zero model mismatches. Strict status 1, exact expected baseline status 0. | `report-check.txt`, `report.crate`, `report.expected.json` |
| v10 selected cases | Eight lists, 46 lines; differences confined to nonzero/repeated beefcodes and bit-17 cases; zero model mismatches. Strict status 1, exact expected baseline status 0. | `v10-cases-check.txt`, `v10-cases.crate`, `v10-cases.expected.json` |
| v9.2 `targeted` | 393 lists, 3,221 lines; 40 lists with output differences and two additional selected-state-only lists. All differences are on bit-17 or RSA paths. Of 129 primitive calls, two RSA results differ from exact math. Zero model mismatches. | `targeted-check.txt`, `targeted.crate`, `targeted.expected.json` |
| v9.2 `optfuzz16` | 100 lists, 3,378 lines; zero output, selected-state, or model differences. Status 0 without an expectation file. | `optfuzz16-check.txt`, `optfuzz16.crate` |
| Normalizer | 12 identical, four changed, zero unresolved equalities. Both real in-memory call-target mutations now report changed. | `normalizer-status.txt`, `normalizer-diff.txt`, `normalizer-mutation-probes.txt`, `normalizer-extents-and-tables.txt` |
| Disc page | At 1280px and 390px: no horizontal overflow, five sections, working theme toggle, no JavaScript exceptions. CSS properties and JavaScript are unchanged. | `disc-page-checks.json` |

The stricter parser also revealed duplicate `cmd3-flip-b22` headers in the
archived `targeted` files. Those originals remain unchanged. The replay uses
`targeted-input.txt` and `targeted-firmware.out`, with occurrence suffixes
applied consistently to duplicate headers only. All other rows are identical
to their sources; `targeted-labels.json` records the renaming.

For example, from `research/`, the reviewed report baseline is checked with:

```
python3 -I tools/emudiff.py elf/CBv92.unpacked.elf elf/review/v92/report.out \
  elf/followup-2026-10-30/report.crate \
  --expected elf/followup-2026-10-30/report.expected.json
```

`tool-regressions.txt` records the test results. `manifest.json` records
source and output hashes so the replay inputs and tool versions are explicit.

### 1.6 Runner and unpacker failure handling (2026-10-31)

Two additional false-success paths were reproduced after the comparison-tool
corrections. `runemu.sh` used bare `wait`, which returned status 0 when a
background headless worker failed. `cbv10_unpack.py` returned status 0 on its
wrong-key diagnostic, and wrote a payload after only warning about an
inflated-size mismatch.

`8ab7cfc` makes worker failures and incomplete outputs fail the runner, while
still waiting for all launched workers. `374dfab` makes invalid unpacking
input fail with status 2 before writing output, including key, length, zlib
completion, and inflated-size validation. The current contracts are also
documented in [v10 §1.5](V10.md#15-key-schedule-fun_01000248-solved) and [v10 §2.1](V10.md#21-method).

The regression suite now has 53 passing tests, including 20 new runner and
unpacker tests. Runner tests use a fake headless executable in temporary
projects; unpacker tests construct synthetic RC4-encrypted zlib bodies. The
suite requires neither Ghidra nor firmware images:

```
python3 -m unittest discover -s research/tools/tests -v
```

`.github/workflows/research.yaml` runs this suite for tool or workflow changes
on pushes and pull requests targeting `research`, and supports manual runs.
The workflow passes local `actionlint` validation; `runemu.sh` passes
ShellCheck and Bash syntax validation.

A separate local check unpacked the identified `CBv10.BOOT.ELF` into a
temporary file using the derived key. The 9,370,970-byte result retains
SHA-256 `9cb83c7ffd28c09ebadf1bba986b34a4dce86bedb03ebb2023c4f944a5d422e3`.
Repeating with an all-zero 20-byte key returned status 2 and preserved the
existing output byte for byte. The source image and archived evidence were
unchanged.
