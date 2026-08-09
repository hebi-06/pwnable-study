# pwnable-study

시스템 해킹(pwnable) 학습 기록. 각 챌린지의 **취약점**, **익스플로잇 원리**, **POC 코드**를 정리.
대부분 [Dreamhack](https://dreamhack.io) 워게임 문제 기반이며, 로컬 재현용 소스(`*.c`)와 익스 스크립트(`poc.py`)가 함께 있음.

## 환경

- 디버거: [pwndbg](./pwndbg) (`source pwndbg/.venv/bin/activate` 후 사용)
- 익스 프레임워크: [pwntools](https://github.com/Gallopsled/pwntools) — `pip install pwntools`

## 챌린지 목록

| 챌린지 | 핵심 기법 | 아키텍처 | 요약 |
|---|---|---|---|
| [test_rop](./test/test_rop) | ret2libc / ROP | x86-64 | BOF → libc 릭 → `system("/bin/sh")` |
| [test_rop_x86](./test/test_rop_x86) | ret2libc / ROP | x86 | 32비트 스택 인자 방식 ROP |
| [test_srop](./test/test_srop) | SROP | x86-64 | `sigreturn`으로 레지스터 전체 조작 |
| [master_canary](./test/master_canary) | Master canary bypass | x86-64 | 스레드 TLS의 마스터 카나리 덮어쓰기 |
| [fho](./test/fho) | `__free_hook` overwrite | x86-64 | AAW로 free hook을 one-gadget으로 |
| [hook](./test/hook) | `__free_hook` + double free | x86-64 | free hook 덮어 double free 우회 |
| [formatstring](./test/formatstring) | Format String Bug | x86 / x86-64 | `%n`으로 임의 주소 쓰기 |
| [_environ](./test/_environ) | `__environ` 스택 릭 | x86-64 | 임의 읽기 → 스택 주소 → flag 릭 |
| [Bypass_Seccomp](./test/Bypass_Seccomp) | Seccomp 우회 | x86-64 | 블랙리스트 밖 syscall로 flag 읽기 |

