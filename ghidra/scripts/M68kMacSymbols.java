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
                    byte[] instructionBytes = inst.getBytes();
                    if (Arrays.equals(ending, Arrays.copyOfRange(instructionBytes, 0, 2))) { // take first 2 bytes only
                        Address symbolAddr = inst.getAddress().addNoWrap(instructionBytes.length);
                        int length = getByte(symbolAddr) & 0xff;
                        symbolAddr = symbolAddr.addNoWrap(1);
                        if (length == 0x80) {
                            length = getByte(symbolAddr) & 0xff;
                            symbolAddr = symbolAddr.addNoWrap(1);
                        } else if (length > 0x80) {
                            length -= 0x80;
                        } else {
                            // TODO: 16 byte fixed length symbols
                            length = 8;
                            symbolAddr = symbolAddr.addNoWrap(-1);
                        }
                        byte[] symbolBytes = getBytes(symbolAddr, length);
                        if (length > 0) {
                            boolean goodSymbol = true;
                            for (int i = 0; i < symbolBytes.length; i++) {
                                int val = symbolBytes[i] & 0xff;
                                if (val < 32 || val > 126) {
                                    // Last char might be unprintable (Symantec C++ bug), omit it
                                    if (i == symbolBytes.length - 1) {
                                        length--;
                                    } else {
                                        goodSymbol = false;
                                    }
                                    break;
                                }
                            }
                            if (goodSymbol) {
                                String symbol = new String(getBytes(symbolAddr, length));
                                symbol = symbol.replace(" ", "_");
                                func.setName(symbol, SourceType.ANALYSIS);
                            }
                        }
                    }
                }
            }
        }
    }
}
