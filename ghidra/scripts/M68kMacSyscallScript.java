//Resolves M68k Mac syscalls (based on ResolveX86orX64LinuxSyscallsScript)
//@category Analysis.M68k
import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import generic.jar.ResourceFile;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.lang.SpaceNames;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class M68kMacSyscallScript extends GhidraScript {

    private static final String SYSCALL_SPACE_NAME = "syscall";

    private static final int SYSCALL_SPACE_LENGTH = 0x10000;

    //this is the name of the userop (aka CALLOTHER) in the pcode translation of the
    //native "syscall" instruction
    private static final String SYSCALL_CALLOTHER = "syscall";

    //file containing map from syscall numbers to syscall names
    private static final String syscallFileName = "m68k_mac_syscalls";

    //the calling convention to use for system calls (must be defined in the appropriate .cspec file)
    private static final String callingConvention = "syscall";

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
            printf("Processor: %s", currentProgram.getLanguage().getProcessor().toString());
            popup("Processor must be 68000");
            return;
        }

        //get the space where the system calls live.
        //If it doesn't exist, create it.
        AddressSpace syscallSpace =
            currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
        if (syscallSpace == null) {
            //don't muck with address spaces if you don't have exclusive access to the program.
            if (!currentProgram.hasExclusiveAccess()) {
                popup("Must have exclusive access to " + currentProgram.getName() +
                    " to run this script");
                return;
            }
            Address startAddr = currentProgram.getAddressFactory().getAddressSpace(
                SpaceNames.OTHER_SPACE_NAME).getAddress(0x0L);
            AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
                SYSCALL_SPACE_NAME, null, this.getClass().getName(), startAddr,
                SYSCALL_SPACE_LENGTH, true, true, true, false, true);
            if (!cmd.applyTo(currentProgram)) {
                popup("Failed to create " + SYSCALL_SPACE_NAME);
                return;
            }
            syscallSpace = currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
        }
        else {
            printf("AddressSpace %s found, continuing...\n", SYSCALL_SPACE_NAME);
        }

        //get all of the functions that contain system calls
        //note that this will not find system call instructions that are not in defined functions
        Map<Address, Long> addressesToSyscalls = getSyscallsInFunctions(currentProgram, monitor);

        if (addressesToSyscalls.isEmpty()) {
            popup("No system calls found (within defined functions)");
            return;
        }

        //get the map from system call numbers to system call names
        Map<Long, String> syscallNumberToData = getSyscallNumberMap();

        DataTypeManager dtm = BuiltInDataTypeManager.getDataTypeManager();

        for (Entry<Address, Long> entry : addressesToSyscalls.entrySet()) {
            Address callSite = entry.getKey();
            Long offset = entry.getValue();
            Address callTarget = syscallSpace.getAddress(offset);
            Function callee = currentProgram.getFunctionManager().getFunctionAt(callTarget);
            String syscallName = "syscall_"+String.format("%08X", offset);
            String[] syscallData = null;
            if (syscallNumberToData.get(offset) != null) {
                syscallData = syscallNumberToData.get(offset).split(",");
            }
            if (syscallData != null) {
                for (int i = 0; i < syscallData.length; i++) {
                    syscallData[i] = syscallData[i].trim();
                }
                syscallName = syscallData[0];
            }
            if (callee == null) {
                callee = createFunction(callTarget, syscallName);
            }
            callee.setCallingConvention(callingConvention);
            try {
                ArrayList<ParameterImpl> params = new ArrayList();
                if (syscallData != null && syscallData.length >= 2) {
                    callee.setCustomVariableStorage(true);
                    String callingConvention = syscallData[1];
                    if (callingConvention.equals("custom")) {
                        for (int i = 2; i < syscallData.length; i++) {
                            String s = syscallData[i];
                            if (s.equals("noreturn")) {
                                callee.setNoReturn(true);
                            } else if (s.startsWith("purge")) {
                                int purgeSize = Integer.decode(s.substring(5).trim());
                                callee.setStackPurgeSize(purgeSize);
                            } else if (i == 2) { // return type
                                if (s.equals("void")) {
                                    callee.setReturn(DataType.VOID, VariableStorage.VOID_STORAGE, SourceType.USER_DEFINED);
                                } else {
                                    String[] returnData = s.split("@");
                                    DataType returnType = parseType(dtm, returnData[0].trim());
                                    VariableStorage returnStorage = parseStorage(currentProgram, returnData[1].trim());
                                    callee.setReturn(returnType, returnStorage, SourceType.USER_DEFINED);
                                }
                            } else {
                                String paramName = s.substring(s.indexOf(" "), s.indexOf("@")).trim();
                                DataType paramType = parseType(dtm, s.substring(0, s.indexOf(" ")));
                                VariableStorage paramStorage = parseStorage(currentProgram, s.substring(s.indexOf("@")+1).trim());
                                params.add(new ParameterImpl(paramName, paramType, paramStorage, currentProgram));
                            }
                        }
                    } else if (callingConvention.equals("pascal")) {
                        int purgeSize = 0;
                        // skip return type
                        for (int i = 3; i < syscallData.length; i++) {
                            String s = syscallData[i];
                            if (s.equals("noreturn")) {
                                continue;
                            } else {
                                purgeSize += parseType(dtm, s.substring(0, s.indexOf(" "))).getLength();
                            }
                        }
                        callee.setStackPurgeSize(purgeSize);
                        int stackPtr = purgeSize;
                        for (int i = 2; i < syscallData.length; i++) {
                            String s = syscallData[i];
                            if (s.equals("noreturn")) {
                                callee.setNoReturn(true);
                            } else if (i == 2) { // return type
                                if (s.equals("void")) {
                                    callee.setReturn(DataType.VOID, VariableStorage.VOID_STORAGE, SourceType.USER_DEFINED);
                                } else {
                                    DataType returnType = parseType(dtm, s);
                                    int size = returnType.getLength();
                                    VariableStorage returnStorage = new VariableStorage(currentProgram, purgeSize, size);
                                    callee.setReturn(returnType, returnStorage, SourceType.USER_DEFINED);
                                }
                            } else {
                                String paramName = s.substring(s.indexOf(" ")).trim();
                                DataType paramType = parseType(dtm, s.substring(0, s.indexOf(" ")));
                                int size = paramType.getLength();
                                VariableStorage paramStorage = new VariableStorage(currentProgram, stackPtr - size, size);
                                stackPtr -= size;
                                params.add(new ParameterImpl(paramName, paramType, paramStorage, currentProgram));
                            }
                        }
                    } else {
                        popup("Invalid calling convention "+callingConvention);
                    }
                }
                callee.replaceParameters(params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
            } catch (InvalidInputException e) {
                popup("Failed to parse syscall data for "+syscallName);
            }
            Reference ref = currentProgram.getReferenceManager().addMemoryReference(callSite,
                callTarget, RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, Reference.MNEMONIC);
            //overriding references must be primary to be active
            currentProgram.getReferenceManager().setPrimary(ref, true);
        }
    }

    private DataType parseType(DataTypeManager dtm, String s) {
        if (s.contains("out")) {
            String dataTypeName = s + "_be_careful_check_address";
            DataType[] datatypes = getDataTypes(dataTypeName);
            DataType dt = null;
            if (datatypes.length == 0) {
                // absolutely awful
                int size = Integer.parseInt(s.substring(3));
                DataType struct = new PointerDataType(new StructureDataType("_"+dataTypeName, 0), size);
                dt = new TypedefDataType(dataTypeName, struct);
            } else {
                dt = datatypes[0];
            }
            return dt;
        } else {
            return dtm.getDataType("/"+s);
        }
    }

    private VariableStorage parseStorage(Program p, String s) throws InvalidInputException {
        if (s.contains("[")) {
            int stackOffset = Integer.decode(s.substring(s.indexOf("[")+1, s.indexOf("]")).trim());
            int size = Integer.decode(s.substring(s.indexOf(":")+1).trim());
            return new VariableStorage(p, stackOffset, size);
        } else {
            return new VariableStorage(p, p.getLanguage().getRegister(s));
        }
    }

    //TODO: better error checking!
    private Map<Long, String> getSyscallNumberMap() {
        Map<Long, String> syscallMap = new HashMap<>();
        ResourceFile rFile = Application.findDataFileInAnyModule(syscallFileName);
        if (rFile == null) {
            popup("Error opening syscall number file, using default names");
            return syscallMap;
        }
        try (FileReader fReader = new FileReader(rFile.getFile(false));
                BufferedReader bReader = new BufferedReader(fReader)) {
            String line = null;
            while ((line = bReader.readLine()) != null) {
                //lines starting with # are comments
                if (!line.startsWith("#")) {
                    String[] parts = line.trim().split(",", 2);
                    Long number = Long.decode(parts[0].trim());
                    syscallMap.put(number, parts[1].trim());
                }
            }
        }
        catch (IOException e) {
            Msg.showError(this, null, "Error reading syscall map file", e.getMessage(), e);
        }
        return syscallMap;
    }

    /**
     * Scans through all of the functions defined in {@code program} and returns
     * a map which takes an address to a syscall number for addresses of
     * system calls
     * @param program program containing functions
     * @param tMonitor monitor
     * @return map address -> syscall number for each syscall
     * @throws CancelledException if the user cancels
     */
    private Map<Address, Long> getSyscallsInFunctions(Program program,
            TaskMonitor tMonitor) throws CancelledException {
        Map<Address, Long> addressesToSyscalls = new HashMap<>();
        for (Function func : program.getFunctionManager().getFunctionsNoStubs(true)) {
            tMonitor.checkCanceled();
            for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
                Long l = instructionToSyscallNumber(inst);
                if (l != null) {
                    addressesToSyscalls.put(inst.getAddress(), l);
                }
            }
        }
        return addressesToSyscalls;
    }

    private Long instructionToSyscallNumber(Instruction inst) {
        try {
            Long retVal = null;
            for (PcodeOp op : inst.getPcode()) {
                if (op.getOpcode() == PcodeOp.CALLOTHER) {
                    int index = (int) op.getInput(0).getOffset();
                    if (inst.getProgram().getLanguage().getUserDefinedOpName(index).equals(
                        SYSCALL_CALLOTHER)) {
                        byte[] bytes = inst.getBytes();
                        retVal = (((long)bytes[0] & 0xFF) << 8) | ((long)bytes[1] & 0xFF);
                    }
                }
            }
            return retVal;
        } catch (MemoryAccessException e) {
            return null;
        }
    }
}
