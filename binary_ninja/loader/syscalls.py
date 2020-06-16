# floating point stuff from SANEMacs.a
FP68K_TYPES = {
    0x0000: "FFEXT (extended: 80-bit float)",
    0x0020: "FFEXT96 (extended: 96-bit float)",
    0x0800: "FFDBL (double: 64-bit float)",
    0x1000: "FFSGL (single: 32-bit float)",
    0x2000: "FFINT (int: 16-bit int)",
    0x2800: "FFLNG (long: 32-bit int)",
    0x3000: "FFCOMP (comp: 64-bit int)"
}

FP68K_OPS = {
    0x0000: "FOADD (add)",
    0x0002: "FOSUB (subtract)",
    0x0004: "FOMUL (multiply)",
    0x0006: "FODIV (divide)",
    0x0008: "FOCMP (compare, no exception from unordered)",
    0x000A: "FOCPX (compare, signal invalid if unordered)",
    0x000C: "FOREM (remainder)",
    0x000E: "FOZ2X (convert to extended)",
    0x0010: "FOX2Z (convert from extended)",
    0x0012: "FOSQRT (square root)",
    0x0014: "FORTI (round to integral value)",
    0x0016: "FOTTI (truncate to integral value)",
    0x0018: "FOSCALB (binary scale)",
    0x001A: "FOLOGB (binary log)",
    0x001C: "FOCLASS (classify)",
    0x0001: "FOSETENV (set environment)",
    0x0003: "FOGETENV (get environment)",
    0x0005: "FOSETHV (set halt vector)",
    0x0007: "FOGETHV (get halt vector)",
    0x0009: "FOD2B (convert decimal to binary)",
    0x000B: "FOB2D (convert binary to decimal)",
    0x000D: "FONEG (negate)",
    0x000F: "FOABS (absolute)",
    0x0011: "FOCPYSGN (copy sign)",
    0x0013: "FONEXT (next-after)",
    0x0015: "FOSETXCP (set exception)",
    0x0017: "FOPROCENTRY (procedure entry)",
    0x0019: "FOPROCEXIT (procedure exit)",
    0x001B: "FOTESTXCP (test exception)"
}
