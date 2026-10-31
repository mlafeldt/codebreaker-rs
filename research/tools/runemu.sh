#!/bin/bash
# Runs EmuP.java (tools/ghidra) headless over one or more corpora for one image.
# v9.2 outputs land in elf/emu/, v10 in elf/emu10/ (<name>.out/.cov/.log each).
# Run from the research/ directory. Needs a Ghidra project per image in $PROJ
# (<img>.gpr + <img>.rep, the analyzed <img>.elf; v10's .elf is made by wrap.py).
# Override analyzeHeadless via $GHIDRA and the project dir via $PROJ.
# Returns nonzero if any worker fails or does not finish writing its outputs.
#
# usage: tools/runemu.sh <v92|v10> <corpus name>...
set -euo pipefail
if [ "$#" -lt 2 ] || [[ "$1" != v92 && "$1" != v10 ]]; then
  echo "usage: $0 <v92|v10> <corpus name>..." >&2
  exit 2
fi
img=$1; shift
# Names form project-copy and output paths. Reject duplicates before launching
# workers so two jobs cannot write the same files or remove each other's copy.
seen=' '
for c in "$@"; do
  if [[ ! "$c" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ || "$seen" == *" $c "* ]]; then
    echo "invalid or duplicate corpus name: $c" >&2
    exit 2
  fi
  seen+="$c "
done
GHIDRA=${GHIDRA:-$(command -v analyzeHeadless || true)}
if [ -z "$GHIDRA" ]; then
  echo "analyzeHeadless not found; set GHIDRA to its path" >&2
  exit 2
fi
PROJ=${PROJ:-proj}
outdir=elf/emu; [ "$img" = v10 ] && outdir=elf/emu10
mkdir -p "$outdir" projcopies

run_corpus() {
  local c=$1 input p summary
  input=elf/emu/$c.txt; [ -f "cases/$c.txt" ] && input=cases/$c.txt
  # one project copy per corpus so they can run in parallel
  p=projcopies/$img-$c; rm -rf "$p"; mkdir -p "$p"; cp -R "$PROJ/$img.gpr" "$PROJ/$img.rep" "$p"/
  # Old files must not satisfy the completion check for a failed new run.
  rm -f "$outdir/$c.out" "$outdir/$c.cov"
  if ! "$GHIDRA" "$p" "$img" -process "$img.elf" -noanalysis -readOnly \
      -scriptPath tools/ghidra -postScript EmuP.java "$input" "$outdir/$c.out" "$outdir/$c.cov" "$img" \
      > "$outdir/$c.log" 2>&1; then
    echo "$img $c failed; see $outdir/$c.log" >&2
    return 1
  fi
  # Ghidra can exit zero even when its post-script throws an exception. EmuP
  # prints this marker only after closing both output files.
  if ! summary=$(grep -oE 'lines=[0-9]+ steps=[0-9]+ ms=[0-9]+' "$outdir/$c.log"); then
    echo "$img $c did not complete; see $outdir/$c.log" >&2
    return 1
  fi
  if [ ! -s "$outdir/$c.out" ] || [ ! -s "$outdir/$c.cov" ]; then
    echo "$img $c has missing or empty outputs; see $outdir/$c.log" >&2
    return 1
  fi
  echo "$img $c done: $summary"
}

pids=()
for c in "$@"; do
  run_corpus "$c" &
  pids+=("$!")
done
status=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    status=1
  fi
done
exit "$status"
