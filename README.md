# M68k Mac Reversing Tools (Binary Ninja and Ghidra)

## Binary Ninja Instructions

**Advantage(s)**: Correct calling convention for syscalls

**Disadvantage(s)**: Decompilation isn't as pretty

1. Make a dump using [dump.py](dump.py).
2. Add [binary_ninja/loader](binary_ninja/loader) and [https://github.com/ubuntor/binaryninja-m68k](https://github.com/ubuntor/binaryninja-m68k) to Binary Ninja plugins.
3. Open the dump. The loader should run automatically and start disassembling.

## Ghidra Instructions

**Advantage(s)**: Nicer looking decompilation, syscalls are functions (so xrefs work)

**Disadvantage(s)**: Return value for syscalls that use pascal calling convention disappears ([Ghidra Issue](https://github.com/NationalSecurityAgency/ghidra/issues/1962))

1. Make a dump using [dump.py](dump.py).
2. Put the files in [ghidra/processor](ghidra/processor) in `$GHIDRA_INSTALL/Ghidra/Processors/68000/data/languages/`.
3. Put []() in `$GHIDRA_INSTALL/Ghidra/Features/Base/data/`.
4. Add the scripts in [ghidra/scripts](ghidra/scripts) to Ghidra scripts. These will be in the `Analysis/M68k` category.
5. Open the dump as processor `68000`, variant `Mac`.
6. Run `M68kMacJankLoader.java` (find functions from jumptable), `M68kMacSymbols.java` (find symbols), and `M68kMacSyscallScript.java` (markup syscalls) in that order.

## TODO
* `_FP68K` (and `_*Dispatch`, `_Pack*`, etc.) routine number labelling
* Label system global vars (see Mac Almanac II)
* Finish all syscalls
* Figure out ghidra issue
* Direct loader for Ghidra from binhex/derez
