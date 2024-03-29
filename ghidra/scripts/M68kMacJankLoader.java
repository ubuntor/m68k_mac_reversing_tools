//Creates functions from jumptable entries
//@category Analysis.M68k

import java.io.*;
import java.util.*;
import generic.jar.ResourceFile;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;

public class M68kMacJankLoader extends GhidraScript {

    private static final byte[] JMP = { (byte) 0x4e, (byte) 0xf9 };
    private static final byte[] THINK_C_START = {
        (byte) 0x42, (byte) 0x78, (byte) 0x0a, (byte) 0x4a, (byte) 0x9d, (byte) 0xce
    };
    private static final int DUMMY_ADDR = 0xFFFFFFFF;

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }
        ResourceFile rFile = Application.findDataFileInAnyModule("m68k_mac_system_globals");
        if (rFile == null) {
            popup("Could not find system globals file");
            return;
        }
        BufferedReader br = new BufferedReader(new FileReader(rFile.getFile(false)));
        String line = null;
        while ((line = br.readLine()) != null) {
            String[] parts = line.trim().split(",", 2);
            Address addr = toAddr(Long.decode(parts[0].trim()));
            String name = parts[1].trim();
            createLabel(addr, name, true, SourceType.ANALYSIS);
        }
        Address a5 = toAddr(getInt(toAddr(0x904))); // CurrentA5

        Address jumptable_entry = a5.addNoWrap(0x20);
        // TODO: actually check the addresses
        try {
            while (true) {
                Address thunkAddr = jumptable_entry.addNoWrap(2);
                if (!Arrays.equals(getBytes(thunkAddr, 2), JMP)) {
                    break;
                }
                int funcAddrInt = getInt(jumptable_entry.addNoWrap(4));
                if (funcAddrInt == DUMMY_ADDR) {
                    jumptable_entry = jumptable_entry.addNoWrap(8);
                    continue;
                }
                Address funcAddr = toAddr(funcAddrInt);
                disassemble(funcAddr);
                createFunction(funcAddr, null);
                disassemble(thunkAddr);
                createFunction(thunkAddr, null);
                jumptable_entry = jumptable_entry.addNoWrap(8);
                printf("created %s %s %s\n", jumptable_entry, funcAddr, thunkAddr);
            }
        } catch (MemoryAccessException|AddressOverflowException e) {
        }
        // first entry in jumptable is entry point
        Address startAddr = toAddr(getInt(a5.addNoWrap(0x20+4)));
        printf("startAddr is %s\n", startAddr);
        createLabel(startAddr, "_start", false, SourceType.ANALYSIS);
        if (Arrays.equals(getBytes(startAddr, THINK_C_START.length), THINK_C_START)) {
            printf("Detected Think C, finding main\n");
            // Think C (Symantec): main offset stored before start
            int mainJumptableOffset = getInt(startAddr.addNoWrap(-4));
            Address entryPoint = toAddr(getInt(a5.addNoWrap(mainJumptableOffset+2))); // skip jmp, get addr
            printf("found main at %s\n", entryPoint);
            addEntryPoint(entryPoint);
            createLabel(entryPoint, "main", false, SourceType.ANALYSIS);
        } else {
            addEntryPoint(startAddr);
        }

        // set value of a5 for the whole program
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        SetRegisterCmd cmd = new SetRegisterCmd(currentProgram.getLanguage().getRegister("A5"),
            space.getMinAddress(),
            space.getMaxAddress(),
            a5.getOffsetAsBigInteger());
        cmd.applyTo(currentProgram);
    }
}
