# pwnable-study

시스템 해킹(pwnable) 학습 기록. 각 챌린지의 **취약점**, **익스플로잇 원리**, **POC 코드**를 정리했습니다.
대부분 [Dreamhack](https://dreamhack.io) 워게임 문제 기반이며, 로컬 재현용 소스(`*.c`)와 익스 스크립트(`poc.py`)가 함께 있습니다.

## 환경

- 디버거: [pwndbg](./pwndbg) (`source pwndbg/.venv/bin/activate` 후 사용)
- 익스 프레임워크: [pwntools](https://github.com/Gallopsled/pwntools) — `pip install pwntools`
- 각 폴더의 `poc.py`는 원격(`remote(...)`) 대상으로 작성되어 있고, 로컬 테스트 시 주석 처리된 `process('./...')`로 전환합니다.

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

## 자주 쓰는 개념 요약

- **BOF (Buffer Overflow)**: 지역 버퍼 경계를 넘겨 스택의 저장된 RBP/RET를 덮음.
- **ret2libc / ROP**: 바이너리·libc의 가젯을 이어붙여 `system`/`execve` 호출로 셸 획득.
- **Canary**: 스택 카나리는 RET 앞에 놓인 랜덤 값. 릭하거나(FSB 등), 스레드 환경에서는 원본(master canary)을 덮어 우회.
- **`__free_hook` / `__malloc_hook`**: glibc가 free/malloc 시 호출하는 함수 포인터. 덮으면 임의 실행. (glibc 2.34에서 제거됨)
- **FSB (Format String Bug)**: `printf(user_input)` 형태. `%p`로 릭, `%n`으로 쓰기.
- **SROP**: `sigreturn` 시스템콜이 스택의 `sigcontext`로 모든 레지스터를 복원하는 점을 악용.

> ⚠️ 실제 flag 파일과 챌린지 zip은 `.gitignore`로 저장소에서 제외되어 있습니다.
