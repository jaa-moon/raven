"""
tests/fixtures_binary.py
-------------------------
Synthetic, deterministic binary fixtures for tools/binary_scanner.py and the
BinaryAssessmentAgent. Every byte is assembled by hand with `struct.pack` --
no real compiled executables and no malware samples, per project policy.

Kept as a standalone module (not tests/conftest.py) because another
in-progress change touches conftest.py concurrently; these builders are
plain functions importable from any test file via
`from tests.fixtures_binary import build_elf64, ...`.
"""

from __future__ import annotations

import struct
from typing import Dict, Iterable, Optional, Sequence

EHDR_SIZE = 64
PHDR_SIZE = 56
DYN_ENTRY_SIZE = 16

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4

DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_BIND_NOW, DT_NULL = 1, 5, 10, 24, 0

ET_EXEC, ET_DYN = 2, 3
EM_X86_64 = 0x3E


def build_elf64(
    needed: Sequence[str] = ("libc.so.6", "libssl.so.3"),
    nx_disabled: bool = False,
    relro: str = "full",           # "full" | "partial" | "none"
    pie: bool = True,
    extra_strings: Sequence[bytes] = (
        b"AKIAABCDEFGHIJKLMNOP",           # matches the AWS Access Key pattern
        b"http://192.168.1.50/admin/panel",  # matches the internal-host pattern
        b"just some padding text here",
    ),
) -> bytes:
    """A minimal, structurally valid ELF64 executable: header + program
    headers (PT_LOAD, PT_DYNAMIC, PT_GNU_STACK, optionally PT_GNU_RELRO) +
    a .dynamic section with DT_NEEDED entries resolved through a .dynstr
    table + trailing embedded strings for the string scanner to find.

    Uses an identity file-offset == virtual-address mapping (one PT_LOAD
    segment spanning the whole file) so DT_STRTAB's "virtual address" can be
    set directly to its file offset -- this keeps the fixture simple while
    still exercising the real vaddr->offset translation code path.
    """
    phnum = 4 if relro != "none" else 3
    dyn_off = EHDR_SIZE + phnum * PHDR_SIZE

    dynstr = bytearray(b"\x00")   # offset 0 conventionally means "no name"
    needed_offsets = []
    for lib in needed:
        needed_offsets.append(len(dynstr))
        dynstr += lib.encode("ascii") + b"\x00"

    flag_entries = [(DT_BIND_NOW, 0)] if relro == "full" else []
    n_entries = len(needed_offsets) + 2 + len(flag_entries) + 1  # +STRTAB +STRSZ +NULL
    dyn_table_size = n_entries * DYN_ENTRY_SIZE
    strtab_off = dyn_off + dyn_table_size

    entries = ([(DT_NEEDED, off) for off in needed_offsets]
              + [(DT_STRTAB, strtab_off), (DT_STRSZ, len(dynstr))]
              + flag_entries + [(DT_NULL, 0)])
    dyn_bytes = b"".join(struct.pack("<qQ", tag, val) for tag, val in entries)
    assert len(dyn_bytes) == dyn_table_size

    strings_blob = b"\x00".join(extra_strings) + b"\x00" if extra_strings else b""
    total_size = strtab_off + len(dynstr) + len(strings_blob)

    e_ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    e_type = ET_DYN if pie else ET_EXEC
    rest = struct.pack("<HHIQQQIHHHHHH",
                       e_type, EM_X86_64, 1,        # e_type, e_machine, e_version
                       0,                             # e_entry
                       EHDR_SIZE,                     # e_phoff
                       0,                              # e_shoff
                       0,                              # e_flags
                       EHDR_SIZE, PHDR_SIZE, phnum, 0, 0, 0)
    ehdr = e_ident + rest
    assert len(ehdr) == EHDR_SIZE

    def phdr(p_type: int, p_flags: int, p_offset: int, p_filesz: int) -> bytes:
        return struct.pack("<IIQQQQQQ", p_type, p_flags, p_offset, p_offset, p_offset, p_filesz, p_filesz, 8)

    phdrs = phdr(PT_LOAD, PF_R | PF_X | PF_W, 0, total_size)
    phdrs += phdr(PT_DYNAMIC, PF_R | PF_W, dyn_off, dyn_table_size)
    stack_flags = PF_R | PF_W | (PF_X if nx_disabled else 0)
    phdrs += phdr(PT_GNU_STACK, stack_flags, 0, 0)
    if relro != "none":
        phdrs += phdr(PT_GNU_RELRO, PF_R, dyn_off, dyn_table_size)
    assert len(phdrs) == phnum * PHDR_SIZE

    return ehdr + phdrs + dyn_bytes + bytes(dynstr) + strings_blob


def build_truncated_elf() -> bytes:
    """ELF magic present, but far too short to hold a full ELF64 header --
    exercises the 'truncated at offset ...' _ParseError path."""
    return b"\x7fELF\x02\x01\x01\x00" + bytes(8)


def build_corrupt_elf_program_headers() -> bytes:
    """A complete, well-formed ELF header, but e_phoff/e_phnum point past
    the end of the file -- exercises graceful handling of a corrupt (not
    just short) structure."""
    e_ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    bogus_phoff = 100_000
    rest = struct.pack("<HHIQQQIHHHHHH",
                       ET_DYN, EM_X86_64, 1, 0,
                       bogus_phoff,                    # e_phoff points nowhere near real data
                       0, 0,
                       EHDR_SIZE, PHDR_SIZE, 5,         # e_phnum = 5, all unreadable
                       0, 0, 0)
    return e_ident + rest


def build_pe(
    machine: int = 0x8664,     # IMAGE_FILE_MACHINE_AMD64
    bits: int = 64,
    aslr: bool = True,
    dep: bool = True,
) -> bytes:
    """A minimal, structurally valid PE/COFF header: DOS stub -> e_lfanew ->
    'PE\\0\\0' -> COFF header -> optional header with Magic and
    DllCharacteristics set. No sections, no import table (real PE
    import-table parsing is a documented, deliberate gap -- see
    tools/binary_scanner.py)."""
    stub = bytearray(64)
    stub[0:2] = b"MZ"
    e_lfanew = 64
    struct.pack_into("<I", stub, 0x3C, e_lfanew)

    sig = b"PE\x00\x00"
    magic = 0x20B if bits == 64 else 0x10B
    opt_header = bytearray(0x46 + 2)
    struct.pack_into("<H", opt_header, 0, magic)
    dll_char = 0
    if aslr:
        dll_char |= 0x0040   # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    if dep:
        dll_char |= 0x0100   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    struct.pack_into("<H", opt_header, 0x46, dll_char)

    coff = struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, len(opt_header), 0x0102)
    return bytes(stub) + sig + coff + bytes(opt_header)


def build_generic_binary_no_known_magic() -> bytes:
    """A file that file_classify() flags is_binary=True via the null-byte
    heuristic, but that matches none of the ELF/PE/Mach-O magics -- exercises
    the 'unsupported format' path for identify()/hardening()/imports()."""
    return b"\x00\x01\x02\x03NOT-A-KNOWN-BINARY-FORMAT\x00\xff\xfe"


def build_macho_header(bits64: bool = True) -> bytes:
    """Header-level-only Mach-O fixture: just the recognized magic bytes
    (file_classify()/tools.binary_scanner only claim header-level support --
    no load commands are parsed, so nothing beyond the magic is needed)."""
    magic = b"\xcf\xfa\xed\xfe" if bits64 else b"\xca\xfe\xba\xbe"
    return magic + b"\x00" * 28
