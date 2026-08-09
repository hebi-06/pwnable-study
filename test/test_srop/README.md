# test_srop (SROP)

**Sigreturn Oriented Programming**. 가젯이 거의 없는 정적/최소 바이너리에서 `sigreturn` 시스템콜 하나로 **모든 레지스터를 원하는 값으로 세팅**해 임의 syscall을 실행한다.

## 대상 코드

```c
int gadget() {
  asm("pop %rax; syscall; ret");   // pop rax; syscall 가젯 제공
}
int main() {
  char buf[16];
  read(0, buf, 1024);              // BOF
}
```

- 컴파일: `gcc -o srop srop.c -fno-stack-protector -no-pie` → 카나리 없음, PIE 없음.
- 오프셋: `buf(16) + SFP(8) = 24`.

## SROP 원리

리눅스에서 시그널 처리가 끝나면 커널은 `sigreturn(15)` 시스템콜을 호출하고, **스택에 저장된 `sigcontext` 구조체 값으로 모든 레지스터(rax, rdi, rsi, rdx, rip, rsp ...)를 복원**한다.

공격자가 이 `sigcontext`(pwntools의 `SigreturnFrame`)를 스택에 직접 깔아두고 `rax=15`로 `sigreturn`을 호출하면, 프레임에 적은 값 그대로 레지스터가 세팅된 채 `rip`로 점프한다. → syscall 인자 전체를 한 번에 제어.

`rax` 세팅과 `syscall` 트리거는 `pop rax; syscall` 가젯으로 해결한다.

## 익스플로잇 흐름

### 1단계 — `read(0, bss, 0x1000)`
`/bin/sh` 문자열과 다음 프레임을 쓸 공간이 필요하므로, 먼저 `SigreturnFrame`으로 `read`를 호출해 bss에 데이터를 입력받는다.

```
gadget(pop rax; syscall) → rax=15 (sigreturn)
frame: rax=0(read), rdi=0, rsi=bss, rdx=0x1000, rip=syscall, rsp=bss
```

### 2단계 — `execve("/bin/sh", 0, 0)`
bss에 `/bin/sh`를 넣고 두 번째 프레임으로 `execve` 실행.

```
frame2: rax=0x3b(execve), rdi=&"/bin/sh", rip=syscall
```

## 핵심 개념

- **왜 SROP인가**: ROP 가젯이 부족해도 `sigreturn` 프레임 하나로 레지스터 전체를 세팅할 수 있어 매우 강력하다.
- `rax=15`(x86-64에서 `sigreturn` 번호)로 세팅 후 `syscall`이 트리거 조건.
- 여러 syscall을 이어가려면 `rsp`를 다음 프레임 위치로 지정해 체인을 잇는다.
