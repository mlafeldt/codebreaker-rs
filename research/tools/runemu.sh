#!/bin/bash
# Runs EmuP.java (tools/ghidra) headless over one or more corpora for one image.
# v9.2 outputs land in elf/emu/, v10 in elf/emu10/ (<name>.out/.cov/.log each).
# Run from the research/ directory. Needs a Ghidra project per image in $PROJ
# (<img>.gpr + <img>.rep, the analyzed <img>.elf; v10's .elf is made by wrap.py).
# Override analyzeHeadless via $GHIDRA and the project dir via $PROJ.
#
# usage: tools/runemu.sh <v92|v10> <corpus name>...
set -e
GHIDRA=${GHIDRA:-$(command -v analyzeHeadless)}
PROJ=${PROJ:-proj}
img=$1; shift
outdir=elf/emu; [ "$img" = v10 ] && outdir=elf/emu10
mkdir -p "$outdir" projcopies
for c in "$@"; do
  in=elf/emu/$c.txt; [ -f "cases/$c.txt" ] && in=cases/$c.txt
  # one project copy per corpus so they can run in parallel
  p=projcopies/$img-$c; rm -rf "$p"; mkdir -p "$p"; cp -R "$PROJ/$img.gpr" "$PROJ/$img.rep" "$p"/
  ( "$GHIDRA" "$p" "$img" -process "$img.elf" -noanalysis -readOnly \
      -scriptPath tools/ghidra -postScript EmuP.java "$in" "$outdir/$c.out" "$outdir/$c.cov" "$img" \
      > "$outdir/$c.log" 2>&1
    echo "$img $c done: $(grep -o 'lines=[0-9]* steps=[0-9]* ms=[0-9]*' "$outdir/$c.log")" ) &
done
wait
