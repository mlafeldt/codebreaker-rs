// For each root address: walk the call tree and print every reached function
// with its basic blocks and instruction listing. Flags instructions that
// Ghidra's MIPS64 language models differently from the R5900 (EE):
// three-operand mult/multu (rd != 0), MMI (opcode 0x1c), lq/sq (0x1e/0x1f),
// and anything Ghidra could not disassemble.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class CallTree extends GhidraScript {
    @Override
    public void run() throws Exception {
        Deque<Function> todo = new ArrayDeque<>();
        Set<Function> seen = new TreeSet<>(Comparator.comparing(Function::getEntryPoint));
        for (String a : getScriptArgs()) {
            Function f = getFunctionAt(toAddr(a));
            if (f == null) f = createFunction(toAddr(a), null);
            if (f != null && seen.add(f)) todo.add(f);
        }
        while (!todo.isEmpty()) {
            Function f = todo.poll();
            for (Function c : f.getCalledFunctions(monitor)) {
                if (seen.add(c)) todo.add(c);
            }
        }
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        for (Function f : seen) {
            println("##### FUNC " + f.getEntryPoint() + " " + f.getName() + " body=" + f.getBody());
            StringBuilder calls = new StringBuilder();
            for (Function c : f.getCalledFunctions(monitor)) calls.append(" ").append(c.getEntryPoint());
            println("calls:" + calls);
            CodeBlockIterator it = bbm.getCodeBlocksContaining(f.getBody(), monitor);
            while (it.hasNext()) {
                CodeBlock b = it.next();
                println("BLOCK " + b.getMinAddress() + " " + b.getMaxAddress());
            }
            for (AddressRange r : f.getBody()) {
                Address a = r.getMinAddress();
                while (a.compareTo(r.getMaxAddress()) <= 0) {
                    Instruction ins = getInstructionAt(a);
                    if (ins == null) {
                        int w = getInt(a);
                        println(a + "  ??? " + String.format("%08x", w) + "  FLAG:undisassembled");
                        a = a.add(4);
                        continue;
                    }
                    int w = getInt(a);
                    int op = (w >>> 26) & 0x3f, fn = w & 0x3f, rd = (w >>> 11) & 0x1f;
                    String flag = "";
                    if (op == 0 && (fn == 0x18 || fn == 0x19) && rd != 0) flag = "  FLAG:mult3";
                    if (op == 0x1c || op == 0x1e || op == 0x1f) flag = "  FLAG:ee-op" + Integer.toHexString(op);
                    if (ins.isInDelaySlot()) flag += "  (delay slot)";
                    println(a + "  " + String.format("%08x", w) + "  " + ins + flag);
                    a = a.add(ins.getLength());
                }
            }
        }
    }
}
