fast bin또한 다른 bin과 마찬가지로 메모리를 적절하게 관린하지 못할 경우 UAF
DFB 같은 취약점이 발생할 수 있음 이때 fast bin에서 double free 탐지를 우회해
청크를 중복해 할당하는 기법을 fastbin dup이라고 함
해당 기법을 활용하면 임의 주소에 청크를 할당 할 수 있음

---fast bin--- 
리눅스의 ptmalloc2에서 작은 크기의 청크를 빠르게 할당 해제하기 
위해 사용하는 bin임
일반적으로 작은 크기의 해제된 청크는 가장 먼저 tcache에서 관리되지만
하나의 tcache가 저장 할 수 있는 최대 청크 개수인 7개를 초과하면 그 이후로는 fast bin에 저장됨

보통 프로세스에서는 크기가 작은 청크들이 큰 청크들에 비해 자주 할당 해제 되는 경우가 많기 때문에
이를 효율적으로 하는 것이 프로그램의 전체적인 성능에 매우 큰 영향을 미치므로 
fstbin은 단일 연결 리스트로 구성되어 있어 속도가 빠른 LIFO로 작동하며 다른 bin들과 다르게 
청크간의 병합이 즉시 일어나지 않아 병합에 사용되는 연산을 아낄수 있음

fast bin에는 헤더를 포함해 32바이트 이상 128바이트 이하의 청크들이 보관되면
16바이트 단위로 7개의 fastbin이 존재함

일반적으로 tcache는 동일한 크기의 청크를 최대 7개까지 저장할 수 있으며 7개를 초과하면 이후에
해제되는 청크는 fastbin에 저장됨 

fastbin은 LIFO로 작동하기 때문에 가장 마지막에 해제된 청크부터 재할당이 이루어지므로 크기가 0x80인 청크 할당 요청이 이루어질때
나중에 해제된 청크인 B가 재할당됨
  

#1 예제코드
// Name: fastbin.c
// Compile: gcc -o fastbin fastbin.c

#include <stdio.h>
#include <stdlib.h> 

void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

int main() {
    char *tcache[7];
    char *chunk1, *chunk2, *chunk3, *chunk4;

    init();

    for (int i = 0; i < 7; i++) { // fill tcachebins
        tcache[i] = calloc(1, 0x40);
        free(tcache[i]);
    }
    
    chunk1 = calloc(1, 0x40);
    chunk2 = calloc(1, 0x40);

    printf("chunk1 addr: %p\n", chunk1);
    printf("chunk2 addr: %p\n", chunk2);
    
    free(chunk1);
    free(chunk2);

    chunk3 = calloc(1, 0x40);
    printf("chunk3 addr: %p\n", chunk3);
  
    chunk4 = calloc(1, 0x40);
    printf("chunk4 addr: %p\n", chunk4);

    return 0;
}
위 코드를 컴파일한 후 pwndbg를 이용해서 fastbin에 청크가 삽입 및 재사용되는 과정을 분석

위 코드는 크기 0x60인 청크를 저장하는 tcache를 모두 채운뒤 fastbin에 청크를 삽입하고 이를 재할당하는 동작을 수행함 
chunk2할당 이후 chunk2해제 이후 그리고 chunk3과 chunk4를 할당한 이후에 각각 중단점을 ㅅ ㅓㄹ정하고 프로그램을 살펴보면 

pwndbg> set disable-randomization on
pwndbg> entry

pwndbg> disass main
   0x0000555555555280 <+112>:   call   0x5555555550c0 <calloc@plt>
   0x0000555555555285 <+117>:   mov    QWORD PTR [rbp-0x60],rax
   0x0000555555555289 <+121>:   mov    esi,0x40
   0x000055555555528e <+126>:   mov    edi,0x1
   0x0000555555555293 <+131>:   call   0x5555555550c0 <calloc@plt>
   0x0000555555555298 <+136>:   mov    QWORD PTR [rbp-0x58],rax
   0x000055555555529c <+140>:   mov    rax,QWORD PTR [rbp-0x60]
   0x00005555555552a0 <+144>:   mov    rsi,rax
   0x00005555555552a3 <+147>:   lea    rax,[rip+0xd5a]        # 0x555555556004
   0x00005555555552aa <+154>:   mov    rdi,rax
   0x00005555555552ad <+157>:   mov    eax,0x0
   0x00005555555552b2 <+162>:   call   0x5555555550b0 <printf@plt>
   0x00005555555552b7 <+167>:   mov    rax,QWORD PTR [rbp-0x58]
   0x00005555555552bb <+171>:   mov    rsi,rax
   0x00005555555552be <+174>:   lea    rax,[rip+0xd50]        # 0x555555556015
   0x00005555555552c5 <+181>:   mov    rdi,rax
   0x00005555555552c8 <+184>:   mov    eax,0x0
   0x00005555555552cd <+189>:   call   0x5555555550b0 <printf@plt>
   0x00005555555552d2 <+194>:   mov    rax,QWORD PTR [rbp-0x60]
pwndbg> b *main+194
Breakpoint 1 at 0x5555555552d2
pwndbg> r

실행을 하면 아래와 같이 chunk1과 chunk2가 각각 0x555555594d0와 0x555555559520에ㅐ 할당된 모습을 확인 가능


heap 명령어 결과
chunk1 addr: 0x5555555594d0
chunk2 addr: 0x555555559520
tcache에 헤더를 포함해 크기 0x50의 청크가 총 7개 저장되어 있으며 0x5555555594c0부터 동일한 크기의 청크 두 개가 연속으로 위치하는 모습을 볼 수 있음


chunk2 해제 
chunk2가 해제된 직수에 중단점을 설정한 후 fastbin 상태
pwndbg> disass main
Dump of assembler code for function main:
   0x00005555555552d9 <+201>:   call   0x555555555090 <free@plt>
   0x00005555555552de <+206>:   mov    rax,QWORD PTR [rbp-0x58]
   0x00005555555552e2 <+210>:   mov    rdi,rax
   0x00005555555552e5 <+213>:   call   0x555555555090 <free@plt>
   0x00005555555552ea <+218>:   mov    esi,0x40
   0x00005555555552ef <+223>:   mov    edi,0x1
   0x00005555555552f4 <+228>:   call   0x5555555550c0 <calloc@plt>
pwndbg> b *main+218
Breakpoint 2 at 0x5555555552ea
pwndbg> c

bins명령어를 이용해 fastbin을 확인해 보면 chunk1과 2가 해제되어 아래와 같이 두청크가 fastbin에 추가되어 있는 모습을 볼 수 있음

pwndbg> bins
tcachebins
0x50 [  7]: 0x555555559480 —▸ 0x555555559430 —▸ 0x5555555593e0 —▸ 0x555555559390 —▸ 0x555555559340 —▸ 0x5555555592f0 —▸ 0x5555555592a0 ◂— 0
fastbins
0x50: 0x555555559510 —▸ 0x5555555594c0 ◂— 0
unsortedbin
empty
smallbins
empty
largebins
empty

또한 free()이후 해당 위치의 메모리를 확인해 보면 아래와 같이 각 청크의 fd자리인 0x55555594d0와 9520에 이전에 해제된 청크의 주소가 sfae linking에 의해 인코딩되어 있음 이떄 fastbin은 단일 연결 리스트 형태이기에 두 청크 모두 bk에는 아무 값도 저장되지 않음

pwndbg> x/30gx 0x5555555594c0
0x5555555594c0: 0x0000000000000000      0x0000000000000051
0x5555555594d0: 0x0000000555555559      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000000
0x555555559500: 0x0000000000000000      0x0000000000000000
0x555555559510: 0x0000000000000000      0x0000000000000051
0x555555559520: 0x000055500000c199      0x0000000000000000
0x555555559530: 0x0000000000000000      0x0000000000000000
0x555555559540: 0x0000000000000000      0x0000000000000000
0x555555559550: 0x0000000000000000      0x0000000000000000
0x555555559560: 0x0000000000000000      0x0000000000020aa1
0x555555559570: 0x0000000000000000      0x0000000000000000
0x555555559580: 0x0000000000000000      0x0000000000000000
0x555555559590: 0x0000000000000000      0x0000000000000000
0x5555555595a0: 0x0000000000000000      0x0000000000000000


chunk3 할당
이후 3을 할당한 뒤 free list를 살펴보면 아래와 같이 chunk3의 주소 출력 직수인 main+264에 중단점을 설정한 뒤 c명령어로 프로그램을 실행해보면 fastbin은 LIFO로 동작하기 때문에 chunk3에 나중에 해제된 chunk2의 주소인 9520이 할당된 모습을 확인 가능

pwndbg> disass main
Dump of assembler code for function main:
   ...
   0x00005555555552e5 <+213>:   call   0x555555555090 <free@plt>
   0x00005555555552ea <+218>:   mov    esi,0x40
   0x00005555555552ef <+223>:   mov    edi,0x1
   0x00005555555552f4 <+228>:   call   0x5555555550c0 <calloc@plt>
   0x00005555555552f9 <+233>:   mov    QWORD PTR [rbp-0x50],rax
   0x00005555555552fd <+237>:   mov    rax,QWORD PTR [rbp-0x50]
   0x0000555555555301 <+241>:   mov    rsi,rax
   0x0000555555555304 <+244>:   lea    rax,[rip+0xd1b]        # 0x555555556026
   0x000055555555530b <+251>:   mov    rdi,rax
   0x000055555555530e <+254>:   mov    eax,0x0
   0x0000555555555313 <+259>:   call   0x5555555550b0 <printf@plt>
   0x0000555555555318 <+264>:   mov    esi,0x40
   ...
pwndbg> b *main+264
Breakpoint 3 at 0x555555555318
pwndbg> c
Continuing.
chunk3 addr: 0x555555559520

bins명령어로 free list를 확인해 보면 2의 헤더 주소는 9510이 fastbin에서 사라진것을 볼수 있음
pwndbg> bins
tcachebins
0x50 [  7]: 0x555555559480 —▸ 0x555555559430 —▸ 0x5555555593e0 —▸ 0x555555559390 —▸ 0x555555559340 —▸ 0x5555555592f0 —▸ 0x5555555592a0 ◂— 0
fastbins
0x50: 0x5555555594c0 ◂— 0
unsortedbin
empty
smallbins
empty
largebins
empty

-chunk4 할당
4를 할당한 뒤 free list 4의 주소를 출력하는 main+305이후에 중단점을 걸고 실행해보면 출력된 4의 주소를 확인해 보면 먼저 해제된 1의 주소와 동일한 94ㅇ0이 할당된것을 확인 가능
pwndbg> disass main
Dump of assembler code for function main:
   ...
   0x0000555555555322 <+274>:   call   0x5555555550c0 <calloc@plt>
   0x0000555555555327 <+279>:   mov    QWORD PTR [rbp-0x48],rax
   0x000055555555532b <+283>:   mov    rax,QWORD PTR [rbp-0x48]
   0x000055555555532f <+287>:   mov    rsi,rax
   0x0000555555555332 <+290>:   lea    rax,[rip+0xcfe]        # 0x555555556037
   0x0000555555555339 <+297>:   mov    rdi,rax
   0x000055555555533c <+300>:   mov    eax,0x0
   0x0000555555555341 <+305>:   call   0x5555555550b0 <printf@plt>
   0x0000555555555346 <+310>:   mov    eax,0x0
   0x000055555555534b <+315>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x000055555555534f <+319>:   sub    rdx,QWORD PTR fs:0x28
   0x0000555555555358 <+328>:   je     0x55555555535f <main+335>
   0x000055555555535a <+330>:   call   0x5555555550a0 <__stack_chk_fail@plt>
   0x000055555555535f <+335>:   leave
   0x0000555555555360 <+336>:   ret
End of assembler dump.
pwndbg> b *main+310
Breakpoint 4 at 0x555555555346
pwndbg> c
Continuing.
chunk4 addr: 0x5555555594d0

free list를 확인하면 아래와 같이 fastbin에서 94c0가 사라진것을 볼 수 있음
pwndbg> bins
tcachebins
0x50 [  7]: 0x555555559480 —▸ 0x555555559430 —▸ 0x5555555593e0 —▸ 0x555555559390 —▸ 0x555555559340 —▸ 0x5555555592f0 —▸ 0x5555555592a0 ◂— 0
fastbins
empty
unsortedbin
empty
smallbins
empty
largebins
empty

- malloc과 calloc
glibc의 malloc/malloc.에 정의되어 있는 함수로 각각 라이브러리의 __libc_malloc()과 __libc_calloc()을 호출함 두 함수 모두 _int_malloc()을 호출해 동적으로 메모리를 할당한다는 점은 유사하지만 재할당 시 tcache사용 여부에서는 차이를 보임 malloc()과 calloc()의 tcache 및 fastbin 사용 방식에 대해 알아보기 위해 함수 내부를 보면

-malloc()
프로그램이 malloc()을 호출하면 내부적으로 __libc_malloc()이 실행됨 malloc()은 아래와 같은 함수 원형을 가지며 단일 인자로 할당할 메모리의 크기를  인자로 전달받음 할당 후에는 할당된 메모리 영영의 주소를 반환함

#include <stdlib.h>

void *malloc(size_t size);
#__libc_malloc()
void *
__libc_malloc (size_t bytes)
{
  ...
  if (!__malloc_initialized)
    ptmalloc_init ();
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes = checked_request2size (bytes);
  if (tbytes == 0)
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache != NULL
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
  ...
  __libc_malloc를 살펴보면 _int_malloc()을 호출하기 전 glibc에서 tcache사용 여부를 컴파일 시점에 결정하는 매크로인 USE_TCACHE의 검사하는 코드를 볼 수 있음 만약 USE_TCACHE의 값을 검하는 코드를 볼 수 있음 만약 USE_TCACHE가 참인 경우 tacache에 먼저 적절한 청크가 있는지 검사한뒤 tcache_get()을 통해 적절한 청크를 할당 받음
  void *
__libc_malloc (size_t bytes)
{
  ...
  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }
  ...

  계속해서 __libc_malloc()을 살펴보면 프로세스가 단일 스레드거나 tcache를 통해 할당 받을 적절한 메모리가 없다면 이후 _int_malloc()을 호출해 메모리를 할당 받는 것을 알 수 있음 결과적으로 malloc()으로 메모리 할당을 요청할 경우 arena를 이용해 메모리를 할당하기 전 tcache의 청크를 우선적으로 할당함

  #calloc()

  calloc()을 호출하면 내부적으로 __libc_calloc()이 실행됨 calloc)(은 아래와 같은 함수 원형을 가지고 있음, size 크기의 데이터를 nmemb개만큼 저장 할 수 있는 공간만큼 메모리를 할당함 성공적으로 할당되면 malloc()과 마찬가지로 할당된 메모리 영역의 주소를 반환함
  void *
__libc_calloc (size_t n, size_t elem_size)
{
  ...
  if (__glibc_unlikely (__builtin_mul_overflow (n, elem_size, &bytes)))
    {
       __set_errno (ENOMEM);
       return NULL;
    }

  sz = bytes;

  if (!__malloc_initialized)
    ptmalloc_init ();

  MAYBE_INIT_TCACHE ();

  if (SINGLE_THREAD_P)
    av = &main_arena;
  else
    arena_get (av, sz);
  ...
  mem = _int_malloc (av, sz);
  ...

  __libc_calloc()은 __builtin_mul_overflow로 크기를 계산한 뒤 _int_malloc()을 호출해 메모리를 할당 받을때 __libc_malloc()과 같이 MAYBE_INIT_TCACHE()를 호출해 tcache를 초기화하는 것은 동일하지만 tcache사용 여부를 검사하거나 tcache에서 청크를 할당받는 로직이 존재하지 않으므로 일반적으로 calloc()을 사용할 경우 tcache와 관련된 공격 기법을 사용하기 힘듬

  void *
__libc_calloc (size_t n, size_t elem_size)
{
  ...
  /* Two optional cases in which clearing not necessary */
  if (chunk_is_mmapped (p))
    {
      if (__builtin_expect (perturb_byte, 0))
        return memset (mem, 0, sz);

      return mem;
    }
  ...
  if (nclears > 9)
    return memset (d, 0, clearsize);

  else
    {
      *(d + 0) = 0;
      *(d + 1) = 0;
      ...
    }
  return mem;
}

또한 __libc_calloc()은 __libc_malloc()과 다르게 할당된 메모리 영역 전체를 0으로 초기화한 뒤 메모리 영역의 주소를 반환함




#Fastbin duplication
// Name: fastbin_dfb.c
// Compile: gcc -o fastbin_dfb fastbin_dfb.c

#include <stdio.h>
#include <stdlib.h> 

int main() {
    char *tcache[7];
    char *chunk;

    for (int i = 0; i < 7 ; i++) {
        tcache[i] = calloc(1, 0x40);
        free(tcache[i]);
    }
    
    chunk = calloc(1, 0x40);

    free(chunk);
    free(chunk);

    return 0;
}

fastbin duplication은 fastbin에 동일한 청크를 중복해 삽입하는 기법을 말함 해당 기법을 활용하면 공격자가 원하는 임의 주소에 청크를 할당 받을 수 있으며 이는 나아가 임의 주소 읽기나 임의 주소 쓰기가 가능해짐

double free를 우회하고 fastbin duplication하는 방법

위코드는 이미 해제되어 fastbin에 저장된 청크를 한번 더 해제하는 예제코드임
컴파일하고 실행하면 아래와 같이 fastbin에서의 double free가 감지되어 프로그램이 비정상적으로 종료되는 것을 확인 할 수 있으므로 fastbin duplication을 트리거하기 위해서는 fastbin에 적용되어 있는 double free 탐지 기법을 우회해야 함
$ ./fastbin_dfb
double free or corruption (fasttop)
Aborted (core dumped)

---정적분석
struct malloc_chunk
struct malloc_chunk;
typedef struct malloc_chunk* mchunkptr;

struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

ptmalloc2에서 각 청크들은 malloc_chunk구조체를 기반으로 관리됨 fd와 bk는 free list에서 각각 이전의 청크와 이후의 청크를 가리키며 fastbin에서는 fd만을 사용함

---__libc_free()---
청크를 해제하기 위해 free()를 호출하면 라이브러리 내부의 __libc_free()가 실행됨
__libc_free()는 해제하고자 하는 청크의 주소를 mem 인자로 전달받아 해당 청크의 포인터 p로 변환후 _int_free()를 호출함
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */
  ...
  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                     
    {
      ...
    }
  else
    {
      MAYBE_INIT_TCACHE ();

      /* Mark the chunk as belonging to the library again.  */
      (void)tag_region (chunk2mem (p), memsize (p));

      ar_ptr = arena_for_chunk (p);
      _int_free (ar_ptr, p, 0);
    }

  __set_errno (err);
}

---_int_free()---
_int_free()는 실질적으로 청크를 해제하는 동작을 수행함 해당 함수에서 fastbin에서의 double free를 감지하는 코드는 아래와 같음
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  ...
  fb = &fastbin (av, idx);

  /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
  mchunkptr old = *fb, old2;

  if (SINGLE_THREAD_P)
    {
  /* Check that the top of the bin is not the record we are going to
     add (i.e., double free).  */
  if (__builtin_expect (old == p, 0))
    malloc_printerr ("double free or corruption (fasttop)");
  p->fd = PROTECT_PTR (&p->fd, old);
  *fb = p;
    }
  else
    do
  {
    /* Check that the top of the bin is not the record we are going to
       add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      malloc_printerr ("double free or corruption (fasttop)");
    old2 = old;
    p->fd = PROTECT_PTR (&p->fd, old);
  }
  ...
  코드를 살펴보면 fb에는 fastbin의 시작 지점을 가리키는 포인터 주소가 old에는 해당 fastbin의 현재 최상단 청크 주소(fasttop)를 대입함을 볼 수 있음 이후 old와 해제하고자 하는 청크 p가 동일한지 비교하고 동일한 경우 double free가 감지되었다는 오류 메세지와 함께 프로그램을 abort시킴
  -> 동일한 청크를 연속해서 해제하지 않는다면 이를 우회 가능

#동적분석
// Name: fastbin_dup.c
// Compile: gcc -o fastbin_dup fastbin_dup.c

#include <stdio.h>
#include <stdlib.h> 

int main() {
    char *tcache[7];
    char *chunk1, *chunk2;

    setvbuf(stdout, 0, 2, 0);

    for (int i = 0; i < 7 ; i++) {
        tcache[i] = calloc(1, 0x40);
        free(tcache[i]);
    }
    
    chunk1 = calloc(1, 0x40);
    chunk2 = calloc(1, 0x40);

    free(chunk1);
    free(chunk2);
    free(chunk1); // vulnerability

    printf("First allocation: %p\n", calloc(1, 0x40));
    printf("Second allocation: %p\n", calloc(1, 0x40));
    printf("Third allocation: %p\n", calloc(1, 0x40));

    return 0;
}
위코드는 fastbin에 적용된 double free 보호 기법을 우회하여 double free bug를 트리거하는 코드임
코드를 살펴보면 21-23행에서 chunk1을 두번 해제 시도하는 모습을 볼 수 있음 컴파일 후 실행 시 다음과 같은 결과를 확인 할 수 있으며 같은 청크가 재할당된 것을 알 수 있음
$ ./fastbin_dup
First allocation: 0x6295506574d0
Second allocation: 0x629550657520
Third allocation: 0x6295506574d0
fastbin은 새롭게 해제되는 청크가 가장 최근에 해제된 청크를 가리키는 단일 연결 리스트 구조를 가짐 만약 chunk1과 chunk2를 번갈아 해제하여 chunk1 -> 2 -> 1 -> 2 -> .... 형태의 순환 사이클을 만들면 재할당받은 chunk1를 통해 free list 에 남아있는 chunk1의 fd를 임의 주소로 변조 할 수 있을것임 결과적으로 이후 재할당 시 조작된 fd가 가리키는 주소에 청크를 할당할 수 있게 됨

청크의 상태를 확인하기 위해 위 코드의 23행에 해당하는 free(chunk1); // bulnerability 직후에 중단점을 설ㅈ3ㅓㅇ한 뒤 bins 명령어로 확인해 보면 아래와 같은 모습을 볼 수 있음 특히 fastbin에 가장 먼저 저장된 청크인 0x6295506574c0의 fd에 이후 해제된 청크의 주소인 0x629550657510이 저장되어 있는 것을 확인 할 수 있음 즉 두 청크가 서로 가리키는 모습을 볼 수 있음
pwndbg> bins
tcachebins
0x50 [  7]: 0x629550657480 —▸ 0x629550657430 —▸ 0x6295506573e0 —▸ 0x629550657390 —▸ 0x629550657340 —▸ 0x6295506572f0 —▸ 0x6295506572a0 ◂— 0
fastbins
0x50: 0x6295506574c0 —▸ 0x629550657510 ◂— 0x6295506574c0
unsortedbin
empty
smallbins
empty
largebins
empty

현재 fastbin의 상태는 fasttop은 가장 마지막에 해제한 청크인 0x6295506574c0이며 두 청크가 서로를 가리키고 있기 때문에 사잍클 구조를 이루게 됨
