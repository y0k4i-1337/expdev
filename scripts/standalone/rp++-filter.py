#!/usr/bin/env python3

import argparse
import logging

logging.basicConfig(level=logging.INFO)

REG_SEGMENTS = {
    "eax": ["ax", "ah", "al"],
    "ebx": ["bx", "bh", "bl"],
    "ecx": ["cx", "ch", "cl"],
    "edx": ["dx", "dh", "dl"],
    "edi": ["di"],
    "esi": ["si"],
    "ebp": ["bp"],
    "esp": ["sp"],
}


class Operand:

    def __init__(self, operand):
        self.operand = operand

    def matches(self, reg, exact):
        if self.operand == reg:
            return True
        elif not exact and reg in self.operand:
            return True
        elif not exact and self.operand in REG_SEGMENTS[reg]:
            return True
        else:
            return False


class Instruction:

    def __init__(self, instr, text):
        self.instr = instr
        self.text = text
        self.operands = []
        self.create_operands()

    def create_operands(self):
        for operand in self.text.split(","):
            if operand != "":
                self.operands.append(Operand(operand))

    def matches_ops(self, filters):
        matches = True
        num_ops = len(self.operands)
        exact = filters.exact
        for i in range(len(filters.ops)):
            reg = filters.ops[i]
            if reg and ((i + 1) > num_ops or not self.operands[i].matches(reg, exact)):
                matches = False
        return matches


class Gadget:

    def __init__(self, text, addrs):
        self.text = text
        self.addrs = addrs
        self.instrs = []
        self.create_instrs()

    def create_instrs(self):
        for instr in self.text.split(";"):
            split_instr = instr.strip().split(" ")
            instr_only = split_instr[0]
            operands = "".join(split_instr[1:])
            self.instrs.append(Instruction(instr_only, operands))


class GadgetEngine:

    def __init__(self, lines):
        self.lines = lines
        self.gadgets = []
        self.create_gadgets()

    def create_gadgets(self):
        for text in self.lines.keys():
            self.gadgets.append(Gadget(text, self.lines[text]))

    def filter(self, filters):
        results = []
        for gadget in self.gadgets:
            # length
            if len(gadget.instrs) > filters.length:
                continue
            # instr
            if filters.instr != "all" and gadget.instrs[0].instr != filters.instr:
                continue
            # last instruction
            if (
                filters.last_instr != "all"
                and filters.last_instr not in gadget.instrs[-1].instr
            ):
                continue
            # ops
            if not gadget.instrs[0].matches_ops(filters):
                continue
            # TODO: find ptrs
            # TODO: exclude immediates
            results.append(gadget)
        self.gadgets = results


def parsehex(value):
    return int(value, 16)


def csvs_to_int_set(csvs):
    return {int(x, 16) for x in csvs.split(",")}


def check_bad_addr(addr, bad):
    """
    Return True if any byte of `addr` is in the collection `bad`.

    `addr` may be a hex string (e.g. '0x41424344' or '41424344') or an int.
    The number of bytes checked is computed from the integer size so that
    small offsets (for example after subtracting a provided base) only
    test the low bytes and do not accidentally examine high bytes that
    are part of an ASLR base.
    """
    # normalize addr to integer (accept hex string or int)
    if isinstance(addr, str):
        addr_int = int(addr, 16)
    else:
        addr_int = int(addr)

    # compute how many bytes are actually needed to represent the value
    # this avoids checking high-order bytes for small offsets
    nbytes = max(1, (addr_int.bit_length() + 7) // 8)

    for shift in range(0, nbytes * 8, 8):
        if ((addr_int >> shift) & 0xFF) in bad:
            return True
    return False


def make_unique(lines, args):
    results = {}
    for line in lines:
        # if base address is specified, consider bad chars on offset only
        addr = line["addr"]
        if args.base:
            addr = hex(int(addr, 16) - args.base)

        if check_bad_addr(addr, args.bad_chars):
            continue
        if line["text"] in results:
            results[line["text"]].append(line["addr"])
        else:
            results[line["text"]] = [line["addr"]]
    return results


def parse(results):
    lines = []
    for idx, result in enumerate(results):
        try:
            line = {}
            result = result.strip()
            split_addr = result.split(": ")
            line["addr"] = split_addr[0]
            line["text"] = split_addr[1].split(" ;  ")[0].strip()
            lines.append(line)
        except Exception as e:
            logging.warning(f"Could not parse line {idx + 1}: {result} - {e}")
            continue
    return lines


def load(file, skip):
    lines = []
    with open(file) as f:
        for i in range(skip):
            next(f)
        lines = f.readlines()
    # return only lines that begin with 0x (addresses)
    return [line for line in lines if line.strip().startswith("0x")]


def main():

    # parse arguments
    parser = argparse.ArgumentParser(
        description="A program for filtering output from rp++"
    )
    parser.add_argument("file")
    parser.add_argument(
        "--skip-lines",
        help="number of lines in file before gadgets (optional)",
        type=int,
        default=0,
        required=False,
    )
    parser.add_argument(
        "--exact",
        help="only return gadgets with the exact registers (e.g. exclude `ax` if `eax` specified)",
        default=False,
        action="store_true",
    )
    parser.add_argument("--op1", help="1st operand (register)")
    parser.add_argument("--op2", help="2nd operand (register)")
    parser.add_argument("--op3", help="3rd operand (register)")
    parser.add_argument("-i", "--instr", help="instruction to search for", default="all")
    parser.add_argument(
        "-l",
        "--length",
        help="max gadget length",
        type=int,
        choices=range(1, 11),
        default=5,
    )
    parser.add_argument(
        "--last-instr",
        help="specify last instruction - default: ret (includes retn)",
        choices=["all", "call", "ret", "retn", "jmp"],
        default="ret",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="known bad characters, format: 00,01,02,03",
        default=[],
        type=csvs_to_int_set,
    )
    parser.add_argument("--base", help="show addresses as base + offset", type=parsehex)

    # process args
    args = parser.parse_args()
    args.ops = [args.op1, args.op2, args.op3]

    # prepare data
    lines = load(args.file, args.skip_lines)
    lines_parsed = parse(lines)  # drops bad chars
    lines_unique = make_unique(lines_parsed, args)

    # create engine / gadgets
    engine = GadgetEngine(lines_unique)

    # filter
    engine.filter(args)

    # print results
    for gadget in engine.gadgets:
        if args.base:
            offset = int(gadget.addrs[0], 16) - args.base
            print("{} + 0x{:x}:  {}".format(hex(args.base), offset, gadget.text))
        else:
            print("{}:  {}".format(gadget.addrs[0], gadget.text))


if __name__ == "__main__":
    main()
