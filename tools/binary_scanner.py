"""
tools/binary_scanner.py
------------------------
Static analysis of local binary executables (ELF / PE / Mach-O): container
format and CPU architecture identification, header-level exploit-mitigation
("hardening") indicators, ELF imported-shared-library enumeration, and
embedded printable-string inspection.

STATIC ONLY. Nothing here ever executes, maps, or loads the target binary --
files are opened read-only and parsed as raw bytes with `struct`. No
third-party binary-parsing library is used (pyelftools/pefile/lief); the
formats parsed here are small, stable, publicly documented structures
(the ELF and PE-COFF specifications).

Deliberate, documented gaps in this milestone (see PROJECT_STATUS.md /
CHANGELOG.md for the authoritative summary):
  * PE import-table parsing (walking the data directories to resolve
    IMAGE_IMPORT_DESCRIPTOR entries to DLL names) is NOT implemented.
    Format/architecture identification and DllCharacteristics-based
    hardening (ASLR/DEP) ARE implemented for PE.
  * Mach-O support is header-level only (magic bytes -> bit width /
    endianness, as tools/inventory.py's file_classify already establishes).
    Load-command parsing (LC_SEGMENT_64, LC_SYMTAB, LC_LOAD_DYLIB, code
    signing, ...) is NOT implemented, so Mach-O hardening indicators and
    imported-dylib enumeration are not available.
  * No dynamic/execution-based analysis of any kind. That is a distinct,
    explicitly deferred future milestone -- not attempted here.

Every parsing entry point below catches malformed/truncated input and
returns a structured, honest result (``parsed: False`` + an ``error`` and
``limitations``) rather than raising or silently reporting "no issues".
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.inventory import file_classify

# -- bounds (keep static analysis cheap and bounded regardless of file size) --------

_MAX_READ_BYTES = 5 * 1024 * 1024     # cap cost of header scans / string extraction
_MAX_STRINGS = 500
_MIN_STRING_LEN = 4
_MAX_PHDRS = 256                      # sanity cap against a corrupt/huge phnum
_MAX_DYN_ENTRIES = 4096
_MAX_NEEDED = 100


class _ParseError(Exception):
    """Internal: header bytes are too short/inconsistent to trust further."""


def _u(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or offset + size > len(data):
        have = max(len(data) - offset, 0) if offset <= len(data) else 0
        raise _ParseError(f"truncated at offset {offset} (need {size} byte(s), have {have}).")
    return data[offset:offset + size]


def _load(path: str) -> Optional[bytes]:
    p = Path(path)
    if not p.is_file():
        return None
    with p.open("rb") as fh:
        return fh.read(_MAX_READ_BYTES)


# ── ELF ──────────────────────────────────────────────────────────────────────────

_ELF_MACHINES = {
    0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64",
    0x16: "S390", 0x28: "ARM", 0x2A: "SuperH", 0x32: "IA-64", 0x3E: "x86-64",
    0xB7: "AArch64", 0xF3: "RISC-V",
}
_ET_NAMES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
_ET_EXEC, _ET_DYN = 2, 3

_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X = 0x1

_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_BIND_NOW = 0x8      # bit in DT_FLAGS
_DF_1_NOW = 0x1          # bit in DT_FLAGS_1


def _parse_elf_header(data: bytes) -> Dict[str, Any]:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise _ParseError("missing ELF magic.")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise _ParseError(f"unknown ELF class byte 0x{ei_class:02x}.")
    if ei_data not in (1, 2):
        raise _ParseError(f"unknown ELF data-encoding byte 0x{ei_data:02x}.")
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    fmt = endian + "HHI" + ("Q" * 3 if is64 else "I" * 3) + "IHHHHHH"
    size = struct.calcsize(fmt)
    (e_type, e_machine, _e_version, _e_entry, e_phoff, _e_shoff, _e_flags,
     _e_ehsize, e_phentsize, e_phnum, _e_shentsize, _e_shnum, _e_shstrndx) = struct.unpack(fmt, _u(data, 16, size))
    return {
        "is64": is64, "endian": endian, "bits": 64 if is64 else 32,
        "endianness": "little" if ei_data == 1 else "big",
        "e_type": e_type, "e_machine": e_machine,
        "e_phoff": e_phoff, "e_phentsize": e_phentsize, "e_phnum": e_phnum,
    }


def _parse_program_headers(data: bytes, hdr: Dict[str, Any]) -> List[Dict[str, Any]]:
    endian, is64 = hdr["endian"], hdr["is64"]
    phoff, phentsize, phnum = hdr["e_phoff"], hdr["e_phentsize"], hdr["e_phnum"]
    if phnum == 0 or phoff == 0:
        return []
    fmt = endian + ("IIQQQQQQ" if is64 else "IIIIIIII")
    size = struct.calcsize(fmt)
    if phentsize < size:
        raise _ParseError(f"e_phentsize ({phentsize}) smaller than the expected program-header size ({size}).")
    out: List[Dict[str, Any]] = []
    for i in range(min(phnum, _MAX_PHDRS)):
        raw = _u(data, phoff + i * phentsize, size)
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack(fmt, raw)
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, p_flags, _p_align = struct.unpack(fmt, raw)
        out.append({"p_type": p_type, "p_flags": p_flags, "p_offset": p_offset,
                    "p_vaddr": p_vaddr, "p_filesz": p_filesz})
    return out


def _vaddr_to_offset(phdrs: List[Dict[str, Any]], vaddr: int) -> Optional[int]:
    for h in phdrs:
        if h["p_type"] == _PT_LOAD and h["p_vaddr"] <= vaddr < h["p_vaddr"] + h["p_filesz"]:
            return h["p_offset"] + (vaddr - h["p_vaddr"])
    return None


def _parse_dynamic(data: bytes, hdr: Dict[str, Any], phdrs: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
    dynseg = next((h for h in phdrs if h["p_type"] == _PT_DYNAMIC), None)
    if dynseg is None:
        return []
    endian, is64 = hdr["endian"], hdr["is64"]
    entsize = 16 if is64 else 8
    fmt = endian + ("qQ" if is64 else "iI")   # d_tag (signed), d_val/d_ptr (read as unsigned)
    count = min(dynseg["p_filesz"] // entsize, _MAX_DYN_ENTRIES) if entsize else 0
    out: List[Tuple[int, int]] = []
    off = dynseg["p_offset"]
    for i in range(count):
        tag, val = struct.unpack(fmt, _u(data, off + i * entsize, entsize))
        if tag == 0:      # DT_NULL terminates the table
            break
        out.append((tag, val))
    return out


def _read_cstr(data: bytes, offset: int, max_len: int = 256) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        end = min(offset + max_len, len(data))
    return data[offset:end].decode("ascii", "replace")


def _needed_libraries(data: bytes, phdrs: List[Dict[str, Any]], dyn: List[Tuple[int, int]]) -> List[str]:
    strtab_vaddr = next((v for t, v in dyn if t == _DT_STRTAB), None)
    if strtab_vaddr is None:
        return []
    strtab_off = _vaddr_to_offset(phdrs, strtab_vaddr)
    if strtab_off is None:
        return []
    names: List[str] = []
    for tag, val in dyn:
        if tag != _DT_NEEDED:
            continue
        name = _read_cstr(data, strtab_off + val)
        if name and name not in names:
            names.append(name)
        if len(names) >= _MAX_NEEDED:
            break
    return names


def _elf_hardening(hdr: Dict[str, Any], phdrs: List[Dict[str, Any]], dyn: List[Tuple[int, int]]) -> Dict[str, Any]:
    gnu_stack = next((h for h in phdrs if h["p_type"] == _PT_GNU_STACK), None)
    nx_stack = "unknown" if gnu_stack is None else ("disabled" if gnu_stack["p_flags"] & _PF_X else "enabled")

    gnu_relro = next((h for h in phdrs if h["p_type"] == _PT_GNU_RELRO), None)
    if gnu_relro is None:
        relro = "none"
    else:
        bind_now = (any(t == _DT_BIND_NOW for t, _ in dyn)
                    or any(t == _DT_FLAGS and (v & _DF_BIND_NOW) for t, v in dyn)
                    or any(t == _DT_FLAGS_1 and (v & _DF_1_NOW) for t, v in dyn))
        relro = "full" if bind_now else "partial"

    pie = {_ET_DYN: "yes", _ET_EXEC: "no"}.get(hdr["e_type"], "unknown")
    return {"nx_stack": nx_stack, "relro": relro, "pie": pie}


# ── PE ───────────────────────────────────────────────────────────────────────────

_PE_MACHINES = {
    0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0x01C4: "ARM (Thumb-2 / ARMv7)",
    0xAA64: "ARM64", 0x0200: "IA-64",
}
_PE_MAGIC_PE32, _PE_MAGIC_PE32PLUS = 0x10B, 0x20B
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040   # ASLR
_IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100      # DEP
_DLL_CHARACTERISTICS_OFFSET = 0x46                # constant across PE32 / PE32+


def _parse_pe_coff(data: bytes) -> Dict[str, Any]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise _ParseError("missing MZ (DOS) magic.")
    (e_lfanew,) = struct.unpack("<I", _u(data, 0x3C, 4))
    if _u(data, e_lfanew, 4) != b"PE\x00\x00":
        raise _ParseError("missing 'PE\\0\\0' signature at e_lfanew.")
    coff_off = e_lfanew + 4
    machine, num_sections, _ts, _symtab, _nsyms, opt_size, characteristics = \
        struct.unpack("<HHIIIHH", _u(data, coff_off, 20))
    opt_off = coff_off + 20
    magic, bits, dll_characteristics = None, None, None
    if opt_size >= 2:
        (magic,) = struct.unpack("<H", _u(data, opt_off, 2))
        bits = 64 if magic == _PE_MAGIC_PE32PLUS else (32 if magic == _PE_MAGIC_PE32 else None)
    if opt_size >= _DLL_CHARACTERISTICS_OFFSET + 2:
        (dll_characteristics,) = struct.unpack("<H", _u(data, opt_off + _DLL_CHARACTERISTICS_OFFSET, 2))
    return {"machine": machine, "num_sections": num_sections, "characteristics": characteristics,
            "bits": bits, "magic": magic, "dll_characteristics": dll_characteristics}


def _pe_hardening(coff: Dict[str, Any]) -> Dict[str, Any]:
    dc = coff.get("dll_characteristics")
    if dc is None:
        return {"aslr": None, "dep": None}
    return {"aslr": bool(dc & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
            "dep": bool(dc & _IMAGE_DLLCHARACTERISTICS_NX_COMPAT)}


# ── Mach-O (header-level only) ──────────────────────────────────────────────────

# Only the two magics tools/inventory.py's file_classify() already recognizes as
# "Mach-O" are reachable through identify()/hardening()/imports() below; the other
# entries document the full, stable constant set for clarity even though this build
# never routes a file to them (file_classify would classify it "binary"/"text" instead).
_MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe": {"bits": 64, "endianness": "little", "magic_name": "MH_MAGIC_64"},
    b"\xce\xfa\xed\xfe": {"bits": 32, "endianness": "little", "magic_name": "MH_MAGIC"},
    b"\xfe\xed\xfa\xcf": {"bits": 64, "endianness": "big", "magic_name": "MH_CIGAM_64"},
    b"\xfe\xed\xfa\xce": {"bits": 32, "endianness": "big", "magic_name": "MH_CIGAM"},
    b"\xca\xfe\xba\xbe": {"bits": None, "endianness": None, "magic_name": "FAT_MAGIC (universal binary)"},
    b"\xbe\xba\xfe\xca": {"bits": None, "endianness": None, "magic_name": "FAT_CIGAM (universal binary)"},
}


def _parse_macho_header(data: bytes) -> Dict[str, Any]:
    if len(data) < 4:
        raise _ParseError("file too short for a Mach-O magic.")
    info = _MACHO_MAGICS.get(bytes(data[:4]))
    if info is None:
        raise _ParseError(f"unrecognized Mach-O magic {bytes(data[:4])!r}.")
    arch = "multiple (universal/fat binary; per-slice architectures not enumerated)" if "FAT" in info["magic_name"] \
        else "unknown (Mach-O load commands not parsed in this milestone)"
    return {"bits": info["bits"], "endianness": info["endianness"], "magic": info["magic_name"], "arch": arch}


# ── public: format/architecture identification ─────────────────────────────────

def identify(path: str) -> Dict[str, Any]:
    """Format + architecture identification. Reuses file_classify() for magic-byte
    format detection, then parses the format-specific header for architecture."""
    info = file_classify(path)
    if not info.get("exists"):
        return {"exists": False, "format": None, "limitations": ["File does not exist."]}
    fmt = info.get("format")
    out: Dict[str, Any] = {"exists": True, "format": fmt, "size": info.get("size"),
                           "is_binary": info.get("is_binary")}
    if not info.get("is_binary"):
        out["limitations"] = ["Not a recognized binary format (looks like text)."]
        return out
    data = _load(path)
    if data is None:
        out["limitations"] = ["File could not be read."]
        return out
    try:
        if fmt == "ELF":
            hdr = _parse_elf_header(data)
            out.update(parsed=True, bits=hdr["bits"], endianness=hdr["endianness"],
                       arch=_ELF_MACHINES.get(hdr["e_machine"], f"unknown (0x{hdr['e_machine']:x})"),
                       type=_ET_NAMES.get(hdr["e_type"], f"unknown ({hdr['e_type']})"))
        elif fmt == "PE":
            coff = _parse_pe_coff(data)
            out.update(parsed=True, bits=coff["bits"], endianness="little",
                       arch=_PE_MACHINES.get(coff["machine"], f"unknown (0x{coff['machine']:x})"),
                       characteristics=coff["characteristics"])
        elif fmt == "Mach-O":
            macho = _parse_macho_header(data)
            out.update(parsed=True, **macho,
                       limitations=["Mach-O support is header-level only in this milestone (magic -> bit "
                                    "width / endianness); load-command parsing (segments, imported dylibs, "
                                    "code signing) is not implemented."])
        else:
            out["limitations"] = [f"Format '{fmt}' is not a supported binary container in this milestone "
                                  "(only ELF, PE, and header-level Mach-O are); no architecture "
                                  "identification was possible."]
    except _ParseError as e:
        out.update(parsed=False, error=str(e))
        out["limitations"] = [f"{fmt} header could not be parsed ({e}); the file may be truncated or corrupt."]
    return out


# ── public: hardening indicators ────────────────────────────────────────────────

def hardening(path: str) -> Dict[str, Any]:
    info = file_classify(path)
    if not info.get("exists") or not info.get("is_binary"):
        return {"exists": info.get("exists", False), "supported": False,
                "limitations": ["File does not exist or is not a recognized binary format."]}
    fmt = info.get("format")
    data = _load(path)
    if data is None:
        return {"exists": True, "format": fmt, "supported": False, "limitations": ["File could not be read."]}
    if fmt == "ELF":
        try:
            hdr = _parse_elf_header(data)
            phdrs = _parse_program_headers(data, hdr)
            dyn = _parse_dynamic(data, hdr, phdrs)
            return {"exists": True, "format": fmt, "supported": True, "parsed": True,
                    "hardening": _elf_hardening(hdr, phdrs, dyn)}
        except _ParseError as e:
            return {"exists": True, "format": fmt, "supported": True, "parsed": False, "error": str(e),
                    "limitations": [f"ELF header/program headers could not be parsed ({e})."]}
    if fmt == "PE":
        try:
            coff = _parse_pe_coff(data)
            return {"exists": True, "format": fmt, "supported": True, "parsed": True,
                    "hardening": _pe_hardening(coff)}
        except _ParseError as e:
            return {"exists": True, "format": fmt, "supported": True, "parsed": False, "error": str(e),
                    "limitations": [f"PE header could not be parsed ({e})."]}
    return {"exists": True, "format": fmt, "supported": False,
            "limitations": [f"Hardening indicators are not implemented for format '{fmt}' in this milestone "
                            "(only ELF and PE are supported)."]}


def missing_hardening_properties(hardening_result: Dict[str, Any], fmt: str) -> List[Dict[str, str]]:
    """Pure classification over an already-computed hardening() result: which
    properties are *confirmed* missing. Never flags 'unknown' -- silence on
    unparseable/absent data, not a guessed finding. Shared, verbatim, by the
    agent (first pass) and the validator (independent re-derivation from a
    freshly re-read file) so both apply the exact same rule to whatever bytes
    were actually observed."""
    out: List[Dict[str, str]] = []
    if fmt == "ELF":
        if hardening_result.get("nx_stack") == "disabled":
            out.append({
                "property": "nx_stack", "label": "NX stack protection (executable stack)", "severity": "medium",
                "description": "PT_GNU_STACK is present with the executable bit (PF_X) set: the stack is "
                               "mapped executable, removing a standard mitigation against stack-based code "
                               "execution.",
                "remediation": "Rebuild with a linker/toolchain default that marks the stack non-executable "
                               "(the default on modern toolchains); avoid code requiring an executable stack.",
            })
        if hardening_result.get("relro") == "none":
            out.append({
                "property": "relro", "label": "RELRO (none)", "severity": "low",
                "description": "No PT_GNU_RELRO segment was found: the GOT remains writable for the life of "
                               "the process. This is a best-effort proxy indicator, not full proof, of "
                               "missing RELRO hardening.",
                "remediation": "Rebuild and link with '-Wl,-z,relro,-z,now' (full RELRO).",
            })
        elif hardening_result.get("relro") == "partial":
            out.append({
                "property": "relro", "label": "RELRO (partial only)", "severity": "low",
                "description": "A PT_GNU_RELRO segment is present but no BIND_NOW indicator (DT_BIND_NOW / "
                               "DF_BIND_NOW / DF_1_NOW) was found: a proxy indicator of partial, not full, "
                               "RELRO.",
                "remediation": "Rebuild and link with '-Wl,-z,relro,-z,now' for full RELRO.",
            })
        if hardening_result.get("pie") == "no":
            out.append({
                "property": "pie", "label": "PIE (position-independent executable)", "severity": "low",
                "description": "e_type is ET_EXEC, not ET_DYN: the binary loads at a fixed base address, "
                               "weakening ASLR effectiveness for this executable. (ET_DYN is a proxy for "
                               "PIE; it is also used for ordinary shared libraries.)",
                "remediation": "Rebuild with '-fPIE -pie' (or the toolchain's default PIE mode).",
            })
    elif fmt == "PE":
        if hardening_result.get("aslr") is False:
            out.append({
                "property": "aslr", "label": "ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)", "severity": "medium",
                "description": "The optional header's DllCharacteristics field does not set "
                               "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040): the image is not marked "
                               "ASLR-eligible.",
                "remediation": "Relink with /DYNAMICBASE (the default in modern MSVC/MinGW toolchains).",
            })
        if hardening_result.get("dep") is False:
            out.append({
                "property": "dep", "label": "DEP (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)", "severity": "medium",
                "description": "The optional header's DllCharacteristics field does not set "
                               "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100): the image does not declare "
                               "compatibility with hardware DEP/NX.",
                "remediation": "Relink with /NXCOMPAT (the default in modern MSVC/MinGW toolchains).",
            })
    return out


# ── public: imported-library enumeration ────────────────────────────────────────

def imports(path: str) -> Dict[str, Any]:
    info = file_classify(path)
    if not info.get("exists") or not info.get("is_binary"):
        return {"exists": info.get("exists", False), "supported": False, "needed": [],
                "limitations": ["File does not exist or is not a recognized binary format."]}
    fmt = info.get("format")
    data = _load(path)
    if data is None:
        return {"exists": True, "format": fmt, "supported": False, "needed": [],
                "limitations": ["File could not be read."]}
    if fmt == "ELF":
        try:
            hdr = _parse_elf_header(data)
            phdrs = _parse_program_headers(data, hdr)
            dyn = _parse_dynamic(data, hdr, phdrs)
            return {"exists": True, "format": fmt, "supported": True, "parsed": True,
                    "needed": _needed_libraries(data, phdrs, dyn)}
        except _ParseError as e:
            return {"exists": True, "format": fmt, "supported": True, "parsed": False, "error": str(e),
                    "needed": [], "limitations": [f"ELF dynamic section could not be parsed ({e})."]}
    if fmt == "PE":
        return {"exists": True, "format": fmt, "supported": False, "needed": [],
                "limitations": ["PE import-table parsing (walking the data directories to resolve "
                                "IMAGE_IMPORT_DESCRIPTOR entries) is not implemented in this milestone; "
                                "format/architecture identification and DllCharacteristics-based hardening "
                                "ARE implemented for PE."]}
    return {"exists": True, "format": fmt, "supported": False, "needed": [],
            "limitations": [f"Imported-library enumeration is not implemented for format '{fmt}' in this "
                            "milestone (only ELF DT_NEEDED parsing is)."]}


# ── public: embedded strings / suspicious indicators ────────────────────────────

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{" + str(_MIN_STRING_LEN).encode() + rb",}")

_SUSPICIOUS_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
    "Private Key Header": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "GitHub Token": re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "Generic API Key Literal": re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{12,}"),
}
_PRIVATE_HOST_PATTERN = re.compile(
    r"(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|(?:[a-z0-9-]+\.)*internal(?:\.[a-z]{2,})?|localhost)(?::\d+)?(?:/[^\s\"']*)?"
)
_DANGEROUS_FUNC_RE = re.compile(r"\b(?:system|exec|execve|execv|popen|strcpy|strcat|sprintf|gets)\b")


def _redact(value: str) -> str:
    v = value.strip()
    if not v:
        return "****"
    return (v[:4] + "*" * max(len(v) - 4, 4))[:48]


def extract_strings(path: str) -> Dict[str, Any]:
    """Format-agnostic: works on any readable file, including one whose
    container format is unrecognized or corrupt (it never parses a header)."""
    p = Path(path)
    if not p.is_file():
        return {"exists": False, "matches": [], "strings_extracted": 0, "limitations": ["File does not exist."]}
    size = p.stat().st_size
    with p.open("rb") as fh:
        data = fh.read(_MAX_READ_BYTES)
    truncated = size > len(data)

    runs: List[Tuple[int, str]] = []
    for m in _PRINTABLE_RUN.finditer(data):
        runs.append((m.start(), m.group().decode("ascii", "replace")))
        if len(runs) >= _MAX_STRINGS:
            break

    matches: List[Dict[str, Any]] = []
    seen = set()
    for offset, s in runs:
        for kind, pat in _SUSPICIOUS_PATTERNS.items():
            mm = pat.search(s)
            if mm and (kind, offset) not in seen:
                seen.add((kind, offset))
                matches.append({"type": kind, "offset": offset, "value_masked": _redact(mm.group(0))})
        hm = _PRIVATE_HOST_PATTERN.search(s)
        if hm and len(hm.group(0)) >= 6 and ("Internal host/URL reference", offset) not in seen:
            seen.add(("Internal host/URL reference", offset))
            matches.append({"type": "Internal host/URL reference", "offset": offset,
                            "value_masked": _redact(hm.group(0))})

    dangerous = sorted({m.group(0) for _, s in runs for m in [_DANGEROUS_FUNC_RE.search(s)] if m})

    return {
        "exists": True, "strings_extracted": len(runs), "strings_capped": len(runs) >= _MAX_STRINGS,
        "bytes_scanned": len(data), "truncated": truncated,
        "matches": matches[:100], "dangerous_function_references": dangerous,
    }
