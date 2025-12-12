#!/usr/bin/env python3
import argparse
import re

import pykd


def get_mod_base(modname):
    # Use WinDbg: lm m <module>
    out = pykd.dbgCommand(f"lm m {modname}")
    m = re.search(r"([0-9a-fA-F`]+)\s+[0-9a-fA-F`]+\s+%s" % modname, out)
    if not m:
        return None
    return int(m.group(1).replace("`", ""), 16)


def get_pe_headers(base):
    """Extract e_lfanew, optional header pointer and preferred ImageBase."""
    e_lfanew = pykd.ptrDWord(base + 0x3C)
    nt = base + e_lfanew
    optional = nt + 0x18
    preferred_base = pykd.ptrDWord(optional + 0x1C)
    return e_lfanew, nt, optional, preferred_base


def parse_import_dir(modname):
    out = pykd.dbgCommand(f"!dh -f {modname}")
    # Import Directory
    # Example line:
    # 168000 [     60C] address [size] of Import Address Table Directory

    m = re.search(
        r"([0-9a-fA-F`]+)\s+\[\s*([0-9a-fA-F`]+)\]\s+address \[size\] of Import Address Table Directory",
        out,
    )
    if not m:
        return None, None
    return int(m.group(1), 16), int(m.group(2), 16)


def parse_iat(iat_raw, base_addr):
    iat = dict()
    for line in iat_raw.splitlines():
        # Example line:
        # 101680b0  7716db30 KERNEL32!WriteFile
        values = line.split()
        if len(values) < 3:
            continue
        iat_addr = int(values[0], 16)
        resolved_addr = int(values[1], 16)
        if "!" not in values[2]:
            continue
        dll_name, func_name = values[2].split("!", 1)
        if dll_name not in iat:
            iat[dll_name] = []
        iat[dll_name].append(
            {
                "iat_addr": iat_addr,
                "offset": iat_addr - base_addr,
                "resolved_addr": resolved_addr,
                "func_name": func_name,
            }
        )
    return iat


def lowest_from_dll(dll_name, iat):
    """Get the IAT entry with the lowest resolved address from a specific DLL."""
    if dll_name not in iat:
        return None
    entries = iat[dll_name]
    lowest_entry = min(entries, key=lambda x: x["resolved_addr"])
    return lowest_entry


def dump_iat(modname, dlls):
    base = get_mod_base(modname)
    if not base:
        print("[!] Could not find module:", modname)
        return
    e_lfanew, nt, optional, preferred_base = get_pe_headers(base)

    print("[+] Module:", modname)
    print()
    print("[+] Base Address        : 0x%08X" % base)
    print("[+] Preferred ImageBase : 0x%08X" % preferred_base)

    imp_rva, imp_size = parse_import_dir(modname)
    if imp_rva is None or imp_rva == 0:
        print("[!] No import directory found.")
        return

    print("[+] Import Directory RVA: 0x%08X  Size: 0x%X" % (imp_rva, imp_size))

    imp_va = base + imp_rva
    print("[+] Import Directory VA : 0x%08X" % imp_va)
    iat_raw = pykd.dbgCommand(f"dps {hex(imp_va)} {hex(imp_va + imp_size)}")
    iat = parse_iat(iat_raw, base)

    for dll_name in iat:
        if dlls and dll_name.upper() not in dlls:
            continue
        print(f"\n[+] DLL: {dll_name}")
        for entry in iat[dll_name]:
            print(
                "    0x%08X  (Offset: 0x%X)  0x%08X  %s"
                % (
                    entry["iat_addr"],
                    entry["offset"],
                    entry["resolved_addr"],
                    entry["func_name"],
                )
            )

    # Print lowest resolved addresses for specified DLLs
    if len(iat) > 0:
        print("\n[+] Lowest resolved addresses from specified DLLs:")
        for dll_name in iat:
            if dlls and dll_name.upper() not in dlls:
                continue
            lowest_entry = lowest_from_dll(dll_name, iat)
            if lowest_entry:
                print(
                    "    DLL: %-12s  0x%08X  (Offset: 0x%X)  0x%08X  %s"
                    % (
                        dll_name,
                        lowest_entry["iat_addr"],
                        lowest_entry["offset"],
                        lowest_entry["resolved_addr"],
                        lowest_entry["func_name"],
                    )
                )
            else:
                print(f"    DLL: {dll_name}  No entries found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dump Import Address Table (IAT) of a module"
    )
    parser.add_argument("module", help="Module name to dump IAT from")
    parser.add_argument("dlls", nargs="*", help="Specific DLLs to display (optional)")
    args = parser.parse_args()
    # normalize dll names to uppercase
    args.dlls = [dll.upper() for dll in args.dlls]
    dump_iat(args.module, args.dlls)
