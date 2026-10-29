// Emulates CodeBreaker's per-line auto decrypt on lists of code lines.
//
// args: <cases.txt> <out.txt> <coverage.txt> <v92|v10>
//
// cases.txt: "=== name" starts a list, then one "AAAAAAAA VVVVVVVV" per line.
// Every list starts from the image's initial memory, calls the reset routine,
// then the per-line entry point once per line. out.txt gets the decrypted
// line and the crypto globals after each call. coverage.txt gets every
// executed instruction address with the first list/line that reached it.
//
// Addresses are for CB v9.2 (research/REVERSING.md §4). The EE differs from
// Ghidra's MIPS64 in places that these functions hit:
// - three-operand mult/multu (rd = LO). Ghidra drops rd or fails to decode
//   the instruction, so every mult/multu with rd != 0 is executed here.
// - memset and memcpy use lq/sq and MMI (pcpyld/pcpyud), which Ghidra
//   doesn't know, so both are replaced with Java versions.
// Ghidra's jr/jalr also emit a setISAMode pcodeop that the emulator doesn't
// implement. The EE has no MIPS16, so it's a no-op here.
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.util.zip.CRC32;

public class EmuP extends GhidraScript {
    // Per-image addresses: reset, per-line decrypt, memset, memcpy, inverse,
    // multiply, RSA wrapper, RSA modulus low word, then the globals: mode,
    // code_lines, V1 flag, beefcodf, opt, key, key copy, seeds.
    static final Map<String, long[]> IMAGES = Map.of(
        "v92", new long[] {0x104548, 0x1042b0, 0x146358, 0x1461b0, 0x1034e0, 0x103580, 0x134020, 0x369000,
                           0x289ac8, 0x289acc, 0x289ad0, 0x36e2fc, 0x36e300, 0x36e2e8, 0x36e1c8, 0x36dcc8},
        "v10", new long[] {0x1052a8, 0x105090, 0x14497c, 0x1447d4, 0x104590, 0x104630, 0x1326e8, 0x9eb330,
                           0x764bd0, 0x764bd4, 0x764bd8, 0x9f057c, 0x9f0580, 0x9f0568, 0x9f0448, 0x9eff48});
    static long RESET, DECRYPT, MEMSET, MEMCPY, INV, MUL, RSA, RSA_N, MODE, LINES, V1, BF, OPT, KEY, KC, SEEDS;
    static final long SENTINEL = 0x01fd0000L, STACK = 0x01ff0000L, BUF = 0x01fe0000L;
    static final long MAX_STEPS = 20_000_000L;

    EmulatorHelper emu;
    Map<Long, String> cov = new TreeMap<>();
    String where;
    long steps;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long[] im = IMAGES.get(args[3]);
        RESET = im[0]; DECRYPT = im[1]; MEMSET = im[2]; MEMCPY = im[3]; INV = im[4]; MUL = im[5]; RSA = im[6];
        RSA_N = im[7]; MODE = im[8]; LINES = im[9]; V1 = im[10]; BF = im[11]; OPT = im[12]; KEY = im[13];
        KC = im[14]; SEEDS = im[15];
        List<String> lines = Files.readAllLines(Paths.get(args[0]));
        PrintWriter out = new PrintWriter(new FileWriter(args[1]));
        String name = null;
        int lineNo = 0;
        long t0 = System.currentTimeMillis(), lineCount = 0;
        for (String l : lines) {
            l = l.trim();
            if (l.isEmpty() || l.startsWith("#")) continue;
            if (l.startsWith("===")) {
                name = l.substring(3).trim();
                out.println("=== " + name);
                reset();
                where = name + ":reset";
                call(RESET);
                lineNo = 0;
                continue;
            }
            String[] p = l.split("\\s+");
            if (l.startsWith("!")) {
                callPrimitive(p, out);
                continue;
            }
            long a = Long.parseLong(p[0], 16), v = Long.parseLong(p[1], 16);
            where = name + ":" + lineNo++;
            emu.writeMemory(addr(BUF), le(a, v));
            emu.writeRegister("a0", BigInteger.valueOf(BUF));
            emu.writeRegister("a1", BigInteger.valueOf(BUF + 4));
            call(DECRYPT);
            out.printf("%08X %08X -> %08X %08X %s%n", a, v, u32(BUF), u32(BUF + 4), state());
            lineCount++;
        }
        out.close();
        PrintWriter c = new PrintWriter(new FileWriter(args[2]));
        for (Map.Entry<Long, String> e : cov.entrySet())
            c.printf("%08x %s%n", e.getKey(), e.getValue());
        c.close();
        println(String.format("lines=%d steps=%d ms=%d", lineCount, steps, System.currentTimeMillis() - t0));
        if (emu != null) emu.dispose();
    }

    // Calls a primitive directly (inside a list, after "=== name"):
    //   !inv X      inverse mod 2^32 (0x1034e0)
    //   !mul A B    A * inverse(B | 1) (0x103580)
    //   !rsa X      X^11 mod 0xfffffffffffffff5 for 64-bit X, via the
    //               wrapper (0x134020) with the arguments the V7 decrypt uses
    void callPrimitive(String[] p, PrintWriter out) throws Exception {
        where = "prim:" + String.join(" ", p);
        long r;
        switch (p[0]) {
        case "!inv":
            emu.writeRegister("a0", BigInteger.valueOf(Long.parseLong(p[1], 16)));
            call(INV);
            r = reg("v0") & 0xffffffffL;
            out.printf("%s %s -> %08X%n", p[0], p[1], r);
            break;
        case "!mul":
            emu.writeRegister("a0", BigInteger.valueOf(Long.parseLong(p[1], 16)));
            emu.writeRegister("a1", BigInteger.valueOf(Long.parseLong(p[2], 16)));
            call(MUL);
            r = reg("v0") & 0xffffffffL;
            out.printf("%s %s %s -> %08X%n", p[0], p[1], p[2], r);
            break;
        case "!rsa":
            long x = Long.parseUnsignedLong(p[1], 16);
            emu.writeMemory(addr(BUF + 0x10), le(x & 0xffffffffL, x >>> 32));
            emu.writeMemory(addr(BUF + 0x20), le(u32(RSA_N), 0xffffffffL));
            emu.writeMemory(addr(BUF + 0x30), new byte[8]);
            emu.writeRegister("a0", BigInteger.valueOf(BUF + 0x30));
            emu.writeRegister("a1", BigInteger.valueOf(BUF + 0x10));
            emu.writeRegister("a2", BigInteger.valueOf(BUF + 0x20));
            emu.writeRegister("a3", BigInteger.valueOf(0xb));
            emu.writeRegister("t0", BigInteger.valueOf(2));
            emu.writeRegister("t1", BigInteger.valueOf(2));
            call(RSA);
            out.printf("%s %s -> %08X%08X%n", p[0], p[1], u32(BUF + 0x34), u32(BUF + 0x30));
            break;
        default:
            throw new RuntimeException("unknown primitive " + p[0]);
        }
    }

    void reset() throws Exception {
        if (emu != null) emu.dispose();
        emu = new EmulatorHelper(currentProgram);
        emu.setMemoryFaultHandler(new MemoryFaultHandler() {
            public boolean uninitializedRead(Address a, int size, byte[] buf, int off) { return true; }
            public boolean unknownAddress(Address a, boolean write) { return false; }
        });
        emu.registerCallOtherCallback("setISAMode", new BreakCallBack() {
            public boolean pcodeCallback(PcodeOpRaw op) { return true; }
        });
        emu.writeMemory(addr(STACK - 0x10000), new byte[0x10000]);
        emu.writeMemory(addr(BUF), new byte[8]);
    }

    void call(long entry) throws Exception {
        emu.writeRegister("sp", BigInteger.valueOf(STACK - 0x100));
        emu.writeRegister("ra", BigInteger.valueOf(SENTINEL));
        emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(entry));
        for (long n = 0; ; n++) {
            if (n > MAX_STEPS) throw new RuntimeException("runaway at " + where);
            long pc = emu.getExecutionAddress().getOffset();
            if (pc == SENTINEL) return;
            cov.putIfAbsent(pc, where);
            steps++;
            if (pc == MEMSET || pc == MEMCPY) {
                long dst = reg("a0"), len = reg("a2") & 0xffffffffL;
                byte[] b;
                if (pc == MEMSET) {
                    b = new byte[(int) len];
                    Arrays.fill(b, (byte) reg("a1"));
                } else {
                    b = emu.readMemory(addr(reg("a1")), (int) len);
                }
                emu.writeMemory(addr(dst), b);
                emu.writeRegister("v0", BigInteger.valueOf(dst));
                emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(reg("ra")));
                continue;
            }
            int w = (int) u32(pc);
            int fn = w & 0x3f, rd = (w >>> 11) & 0x1f;
            if ((w >>> 26) == 0 && (fn == 0x18 || fn == 0x19) && rd != 0) {
                long rs = reg(GPR[(w >>> 21) & 0x1f]), rt = reg(GPR[(w >>> 16) & 0x1f]);
                long p = fn == 0x18 ? (long) (int) rs * (long) (int) rt : (rs & 0xffffffffL) * (rt & 0xffffffffL);
                emu.writeRegister("lo", BigInteger.valueOf((long) (int) p));
                emu.writeRegister("hi", BigInteger.valueOf((long) (int) (p >>> 32)));
                emu.writeRegister(GPR[rd], BigInteger.valueOf((long) (int) p));
                emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(pc + 4));
                continue;
            }
            if (!emu.step(monitor)) throw new RuntimeException("step failed at " + Long.toHexString(pc) + " (" + where + "): " + emu.getLastError());
        }
    }

    String state() throws Exception {
        CRC32 crc = new CRC32();
        crc.update(emu.readMemory(addr(SEEDS), 0x500));
        return String.format("mode=%08X lines=%08X v1=%X bf=%X opt=%X key=%s kc=%s seeds=%08X",
            u32(MODE), u32(LINES), u32(V1), u32(BF), u32(OPT), words(KEY, 5), words(KC, 5), crc.getValue());
    }

    String words(long a, int n) throws Exception {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n; i++) s.append(i == 0 ? "" : ",").append(String.format("%08X", u32(a + 4 * i)));
        return s.toString();
    }

    static final String[] GPR = {"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3",
        "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
        "gp", "sp", "s8", "ra"};

    long reg(String r) { return emu.readRegister(r).longValue(); }

    long u32(long a) throws Exception {
        byte[] b = emu.readMemory(addr(a), 4);
        return (b[0] & 0xffL) | (b[1] & 0xffL) << 8 | (b[2] & 0xffL) << 16 | (b[3] & 0xffL) << 24;
    }

    static byte[] le(long a, long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 4; i++) { b[i] = (byte) (a >> (8 * i)); b[4 + i] = (byte) (v >> (8 * i)); }
        return b;
    }

    Address addr(long a) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a); }
}
