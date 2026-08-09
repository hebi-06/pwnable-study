# test_rop (basic_rop_x64)

64비트 ret2libc. 스택 버퍼 오버플로우로 ROP 체인을 구성해 libc를 릭하고 `system("/bin/sh")`를 호출한다.

## 대상 코드

```c
int main() {
    char buf[0x40] = {};
    initialize();
    read(0, buf, 0x400);        // 0x40 버퍼에 0x400 입력 → BOF
    write(1, buf, sizeof(buf));
    return 0;
}
```

- 보호기법: NX 있음, PIE 없음(고정 주소), 카나리 없음.
- `buf`는 `0x40`인데 `read`는 `0x400`까지 받으므로 리턴 주소를 자유롭게 덮을 수 있다.

## 취약점

- `buf[0x40]` → 저장된 RBP(`0x8`)를 지나 리턴 주소부터 ROP 체인 시작. 즉 오프셋은 `0x40 + 0x8 = 0x48`.

## 익스플로잇 원리

libc 주소를 모르므로 **2단계**로 진행한다.

### 1단계 — libc base 릭
`write(1, read@got, 8)`을 호출해 GOT에 채워진 `read`의 실제 libc 주소를 출력시킨다.

```
pop rdi; ret   → 1            (fd)
pop rsi; pop r15; ret → read@got, dummy   (buf)
write@plt                     (호출)
main                          (다시 main으로 복귀해 2단계 입력)
```

릭한 `read` 주소에서 `libc.symbols['read']` 오프셋을 빼면 `libc_base`. 여기서 `system`, `"/bin/sh"` 주소를 계산한다.

### 2단계 — 셸
```
pop rdi; ret → &"/bin/sh"
system
```

## 핵심 개념

- **GOT 릭**: PLT를 통해 이미 한 번 호출된 함수는 GOT에 실제 libc 주소가 채워져 있다. 이를 출력시켜 ASLR을 우회한다.
- **return-to-main**: 한 번의 입력으로 릭과 셸을 동시에 못 하므로, 릭 후 `main`으로 돌아가 두 번째 페이로드를 받는다.
- SysV amd64 호출 규약: 인자는 `rdi, rsi, rdx, rcx, r8, r9` 순 → 그에 맞는 `pop` 가젯 필요.
