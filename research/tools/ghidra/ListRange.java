// Print instructions in [start, end).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class ListRange extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        for (int i = 0; i + 1 < a.length; i += 2) {
            println("---- " + a[i] + ".." + a[i + 1]);
            Instruction ins = getInstructionAt(toAddr(a[i]));
            while (ins != null && ins.getAddress().compareTo(toAddr(a[i + 1])) < 0) {
                println(ins.getAddress() + "  " + ins);
                ins = ins.getNext();
            }
        }
    }
}
