from binaryninja import *
import struct
import string
import os
from binaryninja.log import log_error

SYSTEM_GLOBALS = {}
__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, "m68k_mac_system_globals"),"r") as f:
    for line in f:
        if line.startswith('#'):
            continue
        l = [i.strip() for i in line.split(",")]
        SYSTEM_GLOBALS[int(l[0],0)] = l[1]

# symbol scanning from:
# MacsBug Reference and Debugging Guide, Appendix D (Procedure Names)
SYMBOL_CHARS = set(map(ord, string.ascii_letters + string.digits + '_%. '))
ENDINGS = set([
b'\x4e\x75', # rts
b'\x4e\xd0', # jmp (A0)
b'\x4e\x74'  # rtd
])
THINK_C_START = b'\x42\x78\x0a\x4a\x9d\xce'

# m68k is big endian
def u16(x):
    return struct.unpack('>H', x)[0]
def u32(x):
    return struct.unpack('>I', x)[0]

def scan_symbol(view, func):
    if view.get_symbol_at(func.start) != None:
        return
    for instr, j in func.instructions:
        if view.read(j, 2) in ENDINGS:
            length = view.read(j+2, 1)[0]
            j += 3
            if length == 0x80:
                length = view.read(j, 1)[0]
                j += 1
            elif length > 0x80:
                length -= 0x80
            else:
                # TODO: 16 byte fixed length symbols
                j -= 1
                length = 8
            symbol = view.read(j, length)
            if length > 0 and all(k in SYMBOL_CHARS for k in symbol):
                view.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, func.start, symbol.decode('utf8')))
                return

class SymbolNotification(BinaryDataNotification):
    def function_added(self, view, func):
        scan_symbol(view, func)
    def function_updated(self, view, func):
        scan_symbol(view, func)

# scan for symbols only after initial analysis
def on_complete(self):
    for func in self.view.functions:
        scan_symbol(self.view, func)
    self.view.register_notification(SymbolNotification())

class MacClassicView(BinaryView):
    name = "Mac Classic"
    long_name = "Mac Classic (jank custom dump format)"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['M68000'].standalone_platform

    @classmethod
    def is_valid_for_data(self, data):
        return data.read(0,8) == b'J\xffA\xffN\xffK\xff'

    def init(self):
        self.add_auto_segment(0, len(self.parent_view), 0, len(self.parent_view),
                              SegmentFlag.SegmentReadable |
                              SegmentFlag.SegmentWritable |
                              SegmentFlag.SegmentExecutable)
        self.add_function(8) # fake function that sets value of a5

        for addr in SYSTEM_GLOBALS:
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, SYSTEM_GLOBALS[addr]))

        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 8, "__fake_set_a5"))
        a5 = u32(self.read(0x904, 4))
        self.add_analysis_completion_event(on_complete)

        jmptable_addr = a5+32
        while True:
            if jmptable_addr+8 > len(self):
                break
            addr = u32(self.read(jmptable_addr+4, 4))
            if addr == 0:
                break
            self.add_function(addr)
            jmptable_addr += 8
        start = u32(self.read(a5+32+4, 4))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, start, "_start"))
        if self.read(start, len(THINK_C_START)) == THINK_C_START:
            # Think C (Symantec): main offset stored before start
            main_jumptable_offset = u32(self.read(start-4, 4))
            entry_point = u32(self.read(a5+main_jumptable_offset+2, 4)) # skip jmp, get addr
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, entry_point, "main"))
        else:
            entry_point = start
        self.store_metadata("entry_point", entry_point)
        self.add_entry_point(entry_point)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.query_metadata("entry_point")

MacClassicView.register()
