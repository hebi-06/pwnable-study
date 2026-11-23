# 실습 예제 모음 (examples)

[기초정리.md](../기초정리.md) · [공략노트.md](../공략노트.md)에서 설명한 개념을
**직접 컴파일 → 익스 → gdb 디버깅**까지 해볼 수 있는 최소 예제들.

모든 예제는 이 devcontainer(Ubuntu, glibc 2.43, gcc)에서 **실제로 빌드·동작을 검증**했음.
각 폴더 구성:

```
vuln.c        취약 소스 (맨 위 주석에 컴파일 명령)
exploit.py    pwntools 익스 (로컬에서 쉘/PWNED 확인)
debug.md      gdb·pwndbg로 내부를 들여다본 실제 출력 + 설명
Makefile      make / make run / make debug
```

## 빠른 시작

```bash
source ../.venv/bin/activate        # pwntools 들어있는 venv
cd 01_bof_ret2win
make            # 컴파일
make run        # 익스 실행 (쉘 → echo PWNED)
make debug      # gdb로 크래시/오프셋 확인
```

> 교육 단순화를 위해 대부분 `-no-pie -fcf-protection=none`로 빌드함(ASLR의 PIE 랜덤화와
> CET(SHSTK/IBT)를 꺼서 고전 기법이 그대로 보이게). 실제 문제는 보호가 더 켜져 있으니
> leak 단계가 추가된다는 점만 다름.

## 예제 목록

| # | 폴더 | 기법 | 핵심 보호 | 한 줄 |
|---|---|---|---|---|
| 01 | [`01_bof_ret2win`](./01_bof_ret2win) | 스택 BOF → ret2win | No Canary | 리턴주소를 `win()`으로 |
| 02 | [`02_canary_leak`](./02_canary_leak) | 카나리 leak | Canary | `%s`로 카나리 흘리고 BOF |
| 03 | [`03_fsb_got`](./03_fsb_got) | 포맷스트링 → GOT overwrite | Partial RELRO | `exit@got`를 `win`으로 |
| 04 | [`04_ret2libc`](./04_ret2libc) | ret2libc (libc leak) | NX | `puts` leak → `system("/bin/sh")` |
| 05 | [`05_heap_tcache`](./05_heap_tcache) | UAF → tcache poisoning | Safe-Linking(2.32+) | heap leak → `fp`를 `win`으로 |

## pwndbg 디버깅 치트시트 (예제에서 쓰는 것들)

```text
# 실행/중단
b *0x401196        특정 주소에 bp          b vuln       함수에 bp
r < input          파일을 stdin으로 실행    c / ni / si  계속 / 다음 / 스텝
# 메모리/레지스터
x/8gx $rsp         스택 8줄(8바이트씩)      x/s 0x402004 문자열
info registers     레지스터 전부            p/x $rdi     특정 레지스터
# 코드/영역
disassemble vuln   디스어셈블               vmmap        매핑/권한
# 힙
heap               chunk 전체               bins         모든 bin
tcachebins         tcache만                 unsortedbin  unsorted만
vis_heap_chunks    색깔 메모리 덤프         malloc_chunk 0x405000  해당 주소를 chunk로 해석
```

### 오프셋 찾기 (cyclic)

```python
from pwn import *
cyclic(0x60)                 # 패턴 입력 생성
cyclic_find('oaaa')          # 크래시 시 rsp/eip 값 → 오프셋
```
