// Decompile functions containing the given addresses; list their callers.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.*;

public class DecompAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<Function> done = new LinkedHashSet<>();
        for (String a : getScriptArgs()) {
            Address addr = toAddr(a);
            Function f = getFunctionContaining(addr);
            if (f == null) { println("NOFUNC " + a); continue; }
            if (!done.add(f)) continue;
            println("===== " + a + " in " + f.getName() + " @ " + f.getEntryPoint() + " =====");
            StringBuilder callers = new StringBuilder();
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                Function c = getFunctionContaining(r.getFromAddress());
                callers.append(" ").append(r.getFromAddress()).append("(").append(c == null ? "?" : c.getName()).append(")");
            }
            println("callers:" + callers);
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "FAILED: " + res.getErrorMessage());
        }
    }
}
