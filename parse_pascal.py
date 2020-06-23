import re
import sys
import os

if len(sys.argv) <= 3:
    print('usage: {} [syscall file] [pascal dir] [out file]'.format(sys.argv[0]))
    sys.exit(1)

# TODO: signed?
types = {
    'LONGINT': 'dword',
    'Fixed': 'dword',
    'Fract': 'dword',
    'DeviceLoopFlags': 'dword',
    'OSType': 'dword', # ??? PACKED ARRAY [1..4] OF CHAR
    'ResType': 'dword', # ??? PACKED ARRAY [1..4] OF CHAR
    'INTEGER': 'word',
    'ScriptCode': 'word',
    'LangCode': 'word',
    'OSErr': 'word',
    'CHAR': 'word', # widechar?
    'Style': 'word',
    'Byte': 'byte',
    'BOOLEAN': 'byte',
    'GrafVerb': 'byte',
    'SignedByte': 'byte',
    'Rect': 'pointer',
    'Pattern': 'pointer',
    'Point': 'pointer',
    'BitMap': 'pointer',
    'Cursor': 'pointer',
    'PenState': 'pointer',
    'Str255': 'pointer',
    'RGBColor': 'pointer',
    'OpenCPicParams': 'pointer',
    'CSpecArray': 'pointer',
    'EventRecord': 'pointer',
    'WindowPeek': 'pointer',
    'FMInput': 'pointer',
    'FMetricRec': 'pointer',
    'Extended': 'pointer',
    'PScrapStuff': 'pointer',
    'SndCommand': 'pointer',
}

sizes = {
    'pointer': 4,
    'dword': 4,
    'word': 2,
    'byte': 1
}

r = re.compile('((procedure|function)\s*\w+(\([^()]*?\))?\s*(:\s*\w+)?;\s*inline\s*\$([0-9a-f]{4});)', flags=(re.M|re.S|re.I))

with open(sys.argv[1]) as f:
    syscalls = f.read().splitlines()

num_to_line = {}
for ind, l in enumerate(syscalls):
    if l.startswith('#'):
        continue
    num = int(l.split(',')[0], 0)
    num_to_line[num] = ind

def transtype(s):
    s = s.strip()
    # TODO: handles are pointers to pointers
    if s.endswith('Ptr') or s.endswith('Handle'):
        return 'pointer'
    if s not in types:
        print(s, "not found")
        return None
    return types[s]

def parse_params(s):
    if s == '':
        return []
    params = []
    for i in s.replace('\n','').split(';'):
        param_name = i.split(':')[0].strip()
        param_type = i.split(':')[1].strip()
        # TODO: pointer to type instead
        if 'VAR' in param_name:
            param_name = param_name.split('VAR')[1].strip()
            param_type = 'Ptr'
        param_type = transtype(param_type)
        if param_type == None:
            return None
        params.append("{} {}".format(param_type, param_name))
    return params

directory = os.fsencode(sys.argv[2])
for ff in os.listdir(directory):
    filename = os.fsdecode(os.path.join(directory, ff))
    if filename.endswith(".p"):
        print("parsing {}".format(filename))
        with open(filename) as f:
            pascal = f.read()
        for match in r.findall(pascal):
            num = int(match[-1],16)
            if num not in num_to_line:
                print("unknown syscall {:04x} {}".format(num, match[0]))
                continue
            linenum = num_to_line[num]
            name = syscalls[linenum].split(',')[1].strip()
            #print(i[1:])
            #print(i[0].replace('\n',''))
            if match[1].lower() == 'procedure':
                returntype = 'void'
            elif match[1].lower() == 'function':
                returnsize = transtype(match[3].split(':')[1])
                if returnsize == None:
                    continue
                # TODO: change to actual type once ghidra bug fixed
                returntype = 'out'+str(sizes[returnsize])
            else:
                1/0
            params = parse_params(match[2][1:-1])
            if params == None:
                continue
            l = ["0x{:04x}".format(num), name, "pascal", returntype] + params
            syscalls[linenum] = ", ".join(l)

with open(sys.argv[3],"w") as f:
    f.write("\n".join(syscalls)+"\n")
