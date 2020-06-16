import struct
import machfs
import macresources
import collections

# make custom jank dump of code

SYSTEM_RAM_SIZE = 0x10000
DUMMY_ADDR = 0xFFFFFFFF

# m68k is big endian
def u16(x):
    return struct.unpack('>H', x)[0]
def u32(x):
    return struct.unpack('>I', x)[0]
def p16(x):
    return struct.pack('>H', x)
def p32(x):
    return struct.pack('>I', x)

def dump_file(image_filename, path, out_filename):
    print("dumping {} to {}".format('/'.join([image_filename]+path), out_filename))
    rsrcs = collections.defaultdict(dict)

    with open(image_filename, 'rb') as f:
        flat = f.read()
        v = machfs.Volume()
        v.read(flat)
        for i in path:
            v = v[i]
        for i in macresources.parse_file(v.rsrc):
            rsrcs[i.type][i.id] = i

    for i in rsrcs:
        print(i)
        for j in rsrcs[i]:
            print("    {}".format(j))

    if b'CODE' not in rsrcs:
        print("Error: no executable code?")
        return

    # TODO: other resource types

    codes = rsrcs[b'CODE']
    crels = rsrcs[b'CREL']

    jumptable = codes[0]

    above_a5_size = u32(jumptable[:4])
    below_a5_size = u32(jumptable[4:8])
    jump_table_size = u32(jumptable[8:12])
    jump_table_offset = u32(jumptable[12:16])
    assert jump_table_size == len(jumptable) - 0x10
    assert jump_table_offset == 0x20

    a5 = below_a5_size + SYSTEM_RAM_SIZE
    for i in codes:
        if i == 0:
            continue
        a5 += len(codes[i])-4

    dump = b''
    header = b'J\xffA\xffN\xffK\xff' # put garbage so address 0 isn't recognized as a string
    # small function to force binary ninja to set the value of a5 as a global reg
    # move.l #a5_value, a5
    # rts
    header += b'\x2a\x7c' + p32(a5) + b'\x4e\x75'

    system_ram = bytearray(header + bytes(SYSTEM_RAM_SIZE - len(header)))
    system_ram[0x904:0x908] = p32(a5)
    dump += system_ram

    segment_bases = {}
    for i in codes:
        if i == 0:
            continue
        segment_header = codes[i][:4]
        segment_data = bytearray(codes[i][4:])
        segment_bases[i] = len(dump)
        first_jumptable_entry_offset = u16(segment_header[:2])
        needs_relocations = False
        if first_jumptable_entry_offset & 0x8000:
            first_jumptable_entry_offset &= ~0x8000
            needs_relocations = True
        jumptable_entry_num = u16(segment_header[2:])
        far_header = False
        if jumptable_entry_num & 0x8000:
            jumptable_entry_num &= ~0x8000
            far_header = True
        print("code segment {}: first offset {:04x}, {} jumptable entries".format(i, first_jumptable_entry_offset, jumptable_entry_num), end='')
        if needs_relocations:
            print(", reloc",end='')
        if far_header:
            print(", far",end='')
        print()
        # relocations as seen in Heaven & Earth (maybe a common compiler?)
        if needs_relocations and jumptable_entry_num > 0:
            for j in range(0, len(crels[i]), 2):
                addr = u16(crels[i][j:j+2]) - 4 # -4 from header
                data = u32(segment_data[addr:addr+4])
                if addr & 0x1:
                    print("TODO: string patch addr {:04x}".format(addr))
                    1/0
                    addr = addr & 0xFFFE
                data2 = (data + a5) & 0xFFFFFFFF
                segment_data[addr:addr+4] = p32(data2)
                print('patched seg {} addr {:04x} ({:08x} -> {:08x})'.format(i, addr, data, data2))
        dump += bytes(segment_data)

    # construct a5 world
    a5_world = b'\x00'*32 # TODO pointer to quickdraw global vars
    for i in range(0x10, len(jumptable), 8):
        # construct a5 jumptable (all loaded jumptable entries)
        entry = jumptable[i:i+8]
        segment_offset = u16(entry[:2])
        segment_num = u16(entry[4:6])
        if segment_num in segment_bases:
            addr = segment_bases[segment_num] + segment_offset
        else:
            print("WARNING: code segment {} not found for jumptable entry {}, replacing with dummy address".format(segment_num, (i-0x10)//8))
            addr = DUMMY_ADDR
        a5_world += p16(segment_num)
        a5_world += b'\x4e\xf9' # jmp
        a5_world += p32(addr)

    dump += bytes(below_a5_size)
    assert len(dump) == a5
    dump += a5_world

    open(out_filename,"wb").write(dump)

#dump_file('HeavenEarth13Color.toast', ['Heaven & Earth'], 'dump_heavenandearth')
#dump_file('disk2.dsk', ["System's Twilight"], 'dump_systemstwilight')
