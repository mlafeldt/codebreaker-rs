# CodeBreaker firmware research

Research compares identified firmware images with the Rust implementation.
Findings belong to the inspected build; matching one version does not establish
behavior for another version or pristine retail provenance.

## Versions

| Version | Notes | Status |
|---|---|---|
| v7 | `V7.md` when research begins | Firmware not yet verified. |
| v8 | `V8.md` when research begins | Firmware not yet verified. |
| v9.2 | [V9.md](V9.md) | Modified image identified, unpacked, decompiled, and emulated against the crate. |
| v10 | [V10.md](V10.md) | Modified loader unpacked; extracted payload compared with v9.2, including state-machine differences. |

Add v7/v8 findings in their own version files using the shared methodology
below. Record each image's identity, provenance, unpacking, address map, crypto
behavior, comparison results, and remaining unknowns. Addresses and models in
the existing tools are specific to the identified v9.2/v10 images.

## Review and follow-up

[REVIEW.md](REVIEW.md) preserves the 2026-10-30 audit, its evidence and
corrections, and the 2026-10-31 runner/unpacker follow-up. The version notes
contain the corrected conclusions; the review retains the historical claims
and their resolution status.

## Files and evidence

Commands in the research notes run from `research/` unless they explicitly
change directory. Preserve archived evidence and its recorded hashes; use
separate files for new version investigations and follow-up runs.

Firmware images and raw tool output are in `elf/`. ELF/BIN images are
gitignored; supporting text evidence can be committed. Scripts are in `tools/`
and `compare/`.

## Branches

`research/` lives only on the `research` branch. `main` never
sees it; instead `main` is merged into `research` when it advances (never the
other way, and `research` is never rebased), so every hash on both branches is
stable and citable:

* Fixes to `src/` that come out of this research go on `main` as normal
  commits, with their own tests, firmware-verified vectors, and commit
  messages that cite the identified CodeBreaker version, not `research/`.
* The version notes cite those fixes by their `main` hash; they may also cite
  `research` commits, since merging (unlike rebasing) leaves them untouched.
* `compare/` (`head = ../..`) builds the crate from the `research` tip, i.e.
  `main` plus this branch, so rerun the checks there to confirm a fix.
* Verified work that stays off `main` gets its own branch, e.g.
  `ffffffff-encryption-options` ([v9.2 §9.5](V9.md#95-ffffffff-encryption-options-bit-16-and-count-since-16299e0-bit-17-left-out)). Cite it by hash too.


## Methodology for further comparisons

Use the identified binary as the reference for that build. Read the existing
findings, evidence, and fix history first; other implementations provide
context, not proof of firmware behavior. Keep implementation changes separate
from a review unless they are part of the requested work. Follow the branch
policy above so cited hashes stay stable.

1. **Identify the artifact.** Record its hash, version, provenance, packer,
   unpacking procedure, and signs of modification. Distinguish inspected paths
   from whole-image authenticity. Keep ELF/BIN images untracked and preserve
   supporting text evidence with its source identity.
2. **Locate and verify the crypto.** Find routines by beefcode immediates,
   seed tables, RC4 keys, and the RSA modulus rather than assuming another
   version's addresses. Compare every constant table with `src/`.
3. **Compare in both directions.** Match each Rust function and branch to
   firmware instructions, then sweep the firmware's branches, callees, and
   globals for missing behavior. Check signedness, shifts, masks, byte order,
   overflow, loop bounds, early returns, and state-update order. Map each state
   field and its initialization/reset rules. Use listings where EE instructions
   make decompilation unreliable.
4. **Differentially exercise the firmware.** Run reset and per-line decrypt on
   random lists and targeted command/line-count cases, beefcodes in each mode,
   extra seed lines, options, and arithmetic boundaries. Validate emulator
   hooks. Compare complete list lengths and outputs; state exactly which state
   fields were compared. Inspect diagnostics rather than trusting exit status
   or normalized equality alone
   ([review F2](REVIEW.md#f2-the-relocation-normalizer-can-hide-real-changes-and-omit-function-tails),
   [F3](REVIEW.md#f3-output-comparison-can-silently-overlook-missing-lines-or-return-success-on-differences)).
5. **Explain coverage gaps.** Record reached blocks and construct inputs for
   unreached paths. Classify each gap as proven unreachable, reachable but
   untested, or unresolved; failure to reach a block does not prove dead code.
   State which paths were modeled, hooked, or actually emulated.
6. **Check encryption and version differences.** Check encryption as an inverse
   of explicit decryption, separating intentional firmware divergences from
   defects. Do not assume auto-detection is an inverse. Compare other versions
   with verified function boundaries and relocation mappings. Trace other
   crypto callers to identify file, loader, or network behavior outside the
   code-line API.
7. **Report reproducible conclusions.** Give a verdict per function, addresses
   and listing evidence, feature status (implemented, intentionally omitted,
   missing, or out of scope), and concrete input/firmware/crate output vectors
   for differences. Include coverage, version changes, tooling limitations,
   and remaining unknowns. Keep observations, model results, and inferences
   distinct; bound compatibility claims to the paths or corpus checked.

## Earlier section references

The former `REVERSING.md` combined all version notes and the review. Section
numbers are now local to each document. Archived evidence and the audit's
original line citations remain unchanged; use this map for older references:

| Former section | Current location |
|---|---|
| §§1–9: v9.2 findings and emulation | [V9.md §§1–9](V9.md#1-the-elf) |
| §10: v10 loader | [V10.md §1](V10.md#1-codebreaker-v10-loader-2026-10-28-corrected-2026-10-30) |
| §11: v10 versus v9.2 | [V10.md §2](V10.md#2-v10-vs-v92-the-full-code-crypto-diff-2026-10-29) |
| §12: audit and follow-up | [REVIEW.md §1](REVIEW.md#1-review-of-all-findings-2026-10-30) |

Subsection numbers follow the same mapping: for example, former §10.5 is
[V10.md §1.5](V10.md#15-key-schedule-fun_01000248-solved), and former §12.5 is
[REVIEW.md §1.5](REVIEW.md#15-follow-up-corrections-2026-10-30).
