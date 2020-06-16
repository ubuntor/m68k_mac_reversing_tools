//Finds MacsBug symbols for each function
//@category Analysis.M68k

import java.io.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class M68kMacSymbols extends GhidraScript {

	private static final byte[][] ENDINGS = {
        { (byte) 0x4e, (byte) 0x75 }, // rts
        { (byte) 0x4e, (byte) 0xd0 }, // jmp (A0)
        { (byte) 0x4e, (byte) 0x74 }  // rtd
    };

	@Override
	protected void run() throws Exception {
		if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
			popup("Processor must be 68000");
			return;
		}

        // get symbol as described in MacsBug Reference and Debugging Guide, Appendix D (Procedure Names)
		for (Function func : currentProgram.getFunctionManager().getFunctionsNoStubs(true)) {
			for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                for (byte[] ending : ENDINGS) {
                    if (Arrays.equals(ending, inst.getBytes())) {
                        Address symbolAddr = inst.getAddress().addNoWrap(2);
                        int length = getByte(symbolAddr) & 0xff;
                        symbolAddr = symbolAddr.addNoWrap(1);
                        if (length == 0x80) {
                            length = getByte(symbolAddr) & 0xff;
                            symbolAddr = symbolAddr.addNoWrap(1);
                        } else if (length > 0x80) {
                            length -= 0x80;
                        } else {
                            // TODO: fixed length symbols?
                            break;
                        }
			            byte[] symbolBytes = getBytes(symbolAddr, length);
                        if (length > 0) {
                            boolean goodSymbol = true;
                            for (byte b : symbolBytes) {
                                int i = (int)b & 0xff;
                                if (i < 32 || i > 126) {
                                    goodSymbol = false;
                                    break;
                                }
                            }
                            if (goodSymbol) {
                                String symbol = new String(symbolBytes);
                                func.setName(symbol, SourceType.ANALYSIS);
                            }
                        }
                    }
                }
			}
		}
	}
}
