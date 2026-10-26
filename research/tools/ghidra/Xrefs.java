// Print every reference to each given address (or [start,end) range given as
// start-end), with the referencing function and instruction.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class Xrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String arg : getScriptArgs()) {
            String[] p = arg.split("-");
            Address lo = toAddr(p[0]), hi = p.length > 1 ? toAddr(p[1]).subtract(1) : lo;
            println("== " + arg);
            AddressIterator it = rm.getReferenceDestinationIterator(new AddressSet(lo, hi), true);
            while (it.hasNext()) {
                Address to = it.next();
                for (Reference r : rm.getReferencesTo(to)) {
                    Function f = getFunctionContaining(r.getFromAddress());
                    println("  " + to + " <- " + r.getFromAddress() + " " + r.getReferenceType() + " "
                        + (f == null ? "?" : f.getEntryPoint()) + "  " + getInstructionAt(r.getFromAddress()));
                }
            }
        }
    }
}
