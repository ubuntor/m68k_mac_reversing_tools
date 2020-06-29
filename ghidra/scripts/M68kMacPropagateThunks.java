//Rewrite memory reference for instructions that call A5 world thunks
//@category Analysis.M68k

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class M68kMacPropagateThunks extends GhidraScript {

    // jsr ...(a5)
    private static final byte[] JSR = { (byte) 0x4e, (byte) 0xad };

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }

        Address a5 = toAddr(getInt(toAddr(0x904))); // CurrentA5

        // get symbol as described in MacsBug Reference and Debugging Guide, Appendix D (Procedure Names)
        for (Function func : currentProgram.getFunctionManager().getFunctionsNoStubs(true)) {
            for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                if (ByteBuffer.wrap(JSR).equals(ByteBuffer.wrap(inst.getBytes(),0,2))) {
                    short offset = getShort(inst.getAddress().addNoWrap(2));
                    // check that the offset points to a thunk in the A5 world
                    if (offset < 0x20 || offset % 8 != 2) {
                        continue;
                    }
                    Address target = toAddr(getInt(a5.addNoWrap(offset+2)));
                    ReferenceManager refman = currentProgram.getReferenceManager();
                    refman.removeAllReferencesFrom(inst.getAddress());
                    Reference ref = refman.addMemoryReference(inst.getAddress(),
                        target, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, Reference.MNEMONIC);
                    refman.setPrimary(ref, true);
                }
            }
        }
    }
}
