//Creates functions from jumptable entries
//@category Analysis.M68k

import java.io.*;
import java.util.*;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class M68kMacJankLoader extends GhidraScript {

	private static final byte[] JMP = { (byte) 0x4e, (byte) 0xf9 };

	@Override
	protected void run() throws Exception {
		if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
			popup("Processor must be 68000");
			return;
		}

        Address a5 = toAddr(getInt(toAddr(0x904)));

        Address jumptable_entry = a5.addNoWrap(0x20);
        while (true) {
            Address thunkAddr = jumptable_entry.addNoWrap(2);
            if (!Arrays.equals(getBytes(thunkAddr, 2), JMP)) {
                break;
            }
            Address funcAddr = toAddr(getInt(jumptable_entry.addNoWrap(4)));
            disassemble(funcAddr);
            createFunction(funcAddr, null);
            disassemble(thunkAddr);
            createFunction(thunkAddr, null);
            jumptable_entry = jumptable_entry.addNoWrap(8);
        }

        // first entry in jumptable is entry point
        addEntryPoint(toAddr(getInt(a5.addNoWrap(0x20+4))));

        // set value of a5 for the whole program
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		SetRegisterCmd cmd = new SetRegisterCmd(currentProgram.getLanguage().getRegister("A5"),
            space.getMinAddress(),
            space.getMaxAddress(),
			a5.getOffsetAsBigInteger());
		cmd.applyTo(currentProgram);
	}
}
