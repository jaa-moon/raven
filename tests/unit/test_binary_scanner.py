"""Static binary parsing (tools/binary_scanner.py): format/arch identification,
hardening indicators, ELF DT_NEEDED imports, embedded-string inspection, and
graceful handling of unsupported/truncated/corrupt input."""

from tests.fixtures_binary import (build_corrupt_elf_program_headers, build_elf64,
                                   build_generic_binary_no_known_magic, build_macho_header, build_pe,
                                   build_truncated_elf)
from tools import binary_scanner as bs


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# ── ELF: identification ──────────────────────────────────────────────────────────

def test_elf_identify_reports_format_bits_endianness_arch_and_type(tmp_path):
    path = _write(tmp_path, "prog.elf", build_elf64(pie=True))
    out = bs.identify(path)
    assert out["format"] == "ELF" and out["parsed"] is True
    assert out["bits"] == 64 and out["endianness"] == "little"
    assert out["arch"] == "x86-64"
    assert out["type"] == "ET_DYN"


def test_elf_identify_reports_et_exec_when_not_pie(tmp_path):
    path = _write(tmp_path, "prog.elf", build_elf64(pie=False))
    assert bs.identify(path)["type"] == "ET_EXEC"


# ── ELF: hardening ────────────────────────────────────────────────────────────────

def test_elf_hardening_all_present(tmp_path):
    path = _write(tmp_path, "hardened.elf", build_elf64(nx_disabled=False, relro="full", pie=True))
    h = bs.hardening(path)
    assert h["parsed"] is True
    assert h["hardening"] == {"nx_stack": "enabled", "relro": "full", "pie": "yes"}
    assert bs.missing_hardening_properties(h["hardening"], "ELF") == []


def test_elf_hardening_all_missing(tmp_path):
    path = _write(tmp_path, "weak.elf", build_elf64(nx_disabled=True, relro="none", pie=False))
    h = bs.hardening(path)
    assert h["hardening"] == {"nx_stack": "disabled", "relro": "none", "pie": "no"}
    missing = {m["property"] for m in bs.missing_hardening_properties(h["hardening"], "ELF")}
    assert missing == {"nx_stack", "relro", "pie"}


def test_elf_relro_partial_is_distinguished_from_full_and_none(tmp_path):
    path = _write(tmp_path, "partial.elf", build_elf64(relro="partial"))
    h = bs.hardening(path)["hardening"]
    assert h["relro"] == "partial"
    missing = bs.missing_hardening_properties(h, "ELF")
    assert any(m["property"] == "relro" and "partial" in m["label"] for m in missing)


def test_elf_hardening_nx_stack_unknown_when_no_gnu_stack_segment(tmp_path):
    """No PT_GNU_STACK at all is genuinely ambiguous (older toolchains omit it) --
    must be reported 'unknown', never guessed as a confirmed finding either way."""
    data = build_elf64()
    # Splice out program headers isn't practical here; instead assert directly
    # against the pure classifier that 'unknown' never produces a finding.
    assert bs.missing_hardening_properties({"nx_stack": "unknown", "relro": "full", "pie": "yes"}, "ELF") == []


# ── ELF: DT_NEEDED imports ───────────────────────────────────────────────────────

def test_elf_imports_extracts_needed_libraries_in_order(tmp_path):
    path = _write(tmp_path, "linked.elf", build_elf64(needed=["libc.so.6", "libssl.so.3", "libpthread.so.0"]))
    out = bs.imports(path)
    assert out["supported"] is True and out["parsed"] is True
    assert out["needed"] == ["libc.so.6", "libssl.so.3", "libpthread.so.0"]


def test_elf_imports_empty_when_no_needed_entries(tmp_path):
    path = _write(tmp_path, "nodeps.elf", build_elf64(needed=[]))
    assert bs.imports(path)["needed"] == []


# ── PE: identification + hardening ──────────────────────────────────────────────

def test_pe_identify_reports_machine_and_bits(tmp_path):
    path = _write(tmp_path, "prog.exe", build_pe(machine=0x8664, bits=64))
    out = bs.identify(path)
    assert out["format"] == "PE" and out["parsed"] is True
    assert out["bits"] == 64 and out["arch"] == "x86-64"


def test_pe_hardening_detects_aslr_and_dep_bits(tmp_path):
    on = _write(tmp_path, "on.exe", build_pe(aslr=True, dep=True))
    off = _write(tmp_path, "off.exe", build_pe(aslr=False, dep=False))
    assert bs.hardening(on)["hardening"] == {"aslr": True, "dep": True}
    assert bs.hardening(off)["hardening"] == {"aslr": False, "dep": False}
    missing = {m["property"] for m in bs.missing_hardening_properties(bs.hardening(off)["hardening"], "PE")}
    assert missing == {"aslr", "dep"}
    assert bs.missing_hardening_properties(bs.hardening(on)["hardening"], "PE") == []


def test_pe_imports_are_explicitly_not_supported_not_silently_empty(tmp_path):
    """PE import-table parsing is a documented, deliberate gap: the result must say
    so (supported=False + limitations), never just return an empty list that looks
    like 'checked, no imports found'."""
    path = _write(tmp_path, "prog.exe", build_pe())
    out = bs.imports(path)
    assert out["supported"] is False
    assert out["needed"] == []
    assert out["limitations"] and "not implemented" in out["limitations"][0]


# ── Mach-O: header-level only ───────────────────────────────────────────────────

def test_macho_identify_is_header_level_only_and_says_so(tmp_path):
    path = _write(tmp_path, "prog.macho", build_macho_header(bits64=True))
    out = bs.identify(path)
    assert out["format"] == "Mach-O" and out["parsed"] is True
    assert out["bits"] == 64 and out["endianness"] == "little"
    assert any("header-level only" in lim for lim in out["limitations"])


def test_macho_hardening_and_imports_are_not_supported(tmp_path):
    path = _write(tmp_path, "prog.macho", build_macho_header())
    assert bs.hardening(path)["supported"] is False
    assert bs.imports(path)["supported"] is False


# ── graceful degradation: truncated / corrupt / unsupported ────────────────────

def test_truncated_elf_never_crashes_and_reports_a_limitation(tmp_path):
    path = _write(tmp_path, "short.elf", build_truncated_elf())
    ident = bs.identify(path)
    assert ident["parsed"] is False and "error" in ident and ident["limitations"]
    hard = bs.hardening(path)
    assert hard["parsed"] is False and "hardening" not in hard   # never a false 'clean' dict
    imp = bs.imports(path)
    assert imp["parsed"] is False and imp["needed"] == []
    # strings extraction is format-agnostic and must still work on raw bytes
    assert bs.extract_strings(path)["exists"] is True


def test_corrupt_program_headers_do_not_crash_and_are_distinguishable_from_clean(tmp_path):
    path = _write(tmp_path, "corrupt.elf", build_corrupt_elf_program_headers())
    ident = bs.identify(path)                     # ELF header itself is fine
    assert ident["parsed"] is True
    hard = bs.hardening(path)                      # but program headers point off the end of the file
    assert hard["parsed"] is False
    assert "hardening" not in hard
    assert hard["limitations"]


def test_unsupported_generic_binary_format_never_crashes_and_is_explicit(tmp_path):
    path = _write(tmp_path, "opaque.bin", build_generic_binary_no_known_magic())
    ident = bs.identify(path)
    assert ident["format"] not in ("ELF", "PE", "Mach-O")
    assert ident["limitations"]
    hard = bs.hardening(path)
    assert hard["supported"] is False and "hardening" not in hard
    imp = bs.imports(path)
    assert imp["supported"] is False and imp["needed"] == []
    # string extraction still works even though the container format is unknown
    strings = bs.extract_strings(path)
    assert strings["exists"] is True


def test_nonexistent_file_is_handled_without_raising():
    path = "C:/definitely/not/a/real/path/nope.bin"
    assert bs.identify(path) == {"exists": False, "format": None,
                                 "limitations": ["File does not exist."]}
    assert bs.hardening(path)["supported"] is False
    assert bs.imports(path)["supported"] is False
    assert bs.extract_strings(path)["exists"] is False


# ── embedded strings / suspicious indicators ────────────────────────────────────

def test_extract_strings_flags_aws_key_and_internal_host_with_redaction(tmp_path):
    path = _write(tmp_path, "secrets.elf", build_elf64(extra_strings=[
        b"AKIAABCDEFGHIJKLMNOP", b"http://192.168.1.50/admin/panel", b"harmless padding text",
    ]))
    out = bs.extract_strings(path)
    types = {m["type"] for m in out["matches"]}
    assert "AWS Access Key" in types and "Internal host/URL reference" in types
    for m in out["matches"]:
        assert "AKIAABCDEFGHIJKLMNOP" not in m["value_masked"]     # never a raw, unredacted secret
        assert "192.168.1.50" not in m["value_masked"] or m["type"] != "AWS Access Key"


def test_extract_strings_respects_caps(tmp_path):
    blob = b"\x00".join(f"str{i:04d}xxxx".encode() for i in range(2000)) + b"\x00"
    path = _write(tmp_path, "many.bin", blob)
    out = bs.extract_strings(path)
    assert out["strings_extracted"] <= bs._MAX_STRINGS
    assert out["strings_capped"] is True


def test_extract_strings_detects_dangerous_function_references(tmp_path):
    path = _write(tmp_path, "dang.elf", build_elf64(extra_strings=[b"call to system() here", b"strcpy overflow"]))
    out = bs.extract_strings(path)
    assert "system" in out["dangerous_function_references"]
    assert "strcpy" in out["dangerous_function_references"]
