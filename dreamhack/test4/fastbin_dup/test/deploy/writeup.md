# fastbin duplication
fastbin duplication을 활용해 임의 주소에 청크를 할당하는 공격 기법

fastbin duplication은 double free bug를 이용해 청크를 fastbin의 free list에 중복해 연결하는 기법임
fastbin duplication을 이용하면 스택 등 임의 주소에 청크를 할당 할 수 있으며 나아가 임의 주소 읽기 임의 주소 쓰기를 수행 가능

## 원리 
동일한 청크가 두번 해제된 뒤 한번의 재할당이 이루어지면 해당 청크는 여전히 free list에 남아 있기 떄문에 할당됨과 동시에 해제된 청크가 됨
이처럼 중첩 상태인 청크에 데이터를 작성해 fd를 조작하면 fastbin에 임의 주소를 추가 할수 있음

이 과정을 자세히 알아보기 위해 fastbin의 두 청크가 double free로 인해 서로를 가리키고 있는 상황을 가정해 보면 이러한 상태에서 할당과 동시에 값을 입력하는 과정을 총 4번 거친다고 가정하면 다음과 같은 순서로 임의 위치에 청크를 할당 하 수 있음 이해의 편의를 위해 safe linking이 적용되지 않은 환경을 가정하여 설명하면
fastbin duplication으로 인해 두 청크가 서로를 가리키고 있는 상태를 가정해 보면 이때 가장 마지막으로 해제된 청크는 0x601800에 위치하는 청크로 할당을 요청하면 해당 청크가 가장 먼저 할당됨
이후 chunk1 = calloc(0x70, 1); strcpy(chunk1, "AAAAAAAA"); 를 통해 새로운 청크르 할당하고 해당 청크의 fd를 AAAAAAA로 변조하면 fastbin에 임의의 값을 추가 할수 있음
할당을 반복해 fastbin을 순차적으로 비우면 fastbin의 최상단에 우리가 입력한 값인 0x414141414141414141 가 위치 할 것임 이후 chunk4 = calloc(0x70, 1); strcpy(chunk4, "DDDDDDDD");와 같이 할당을 요청하면 해당 값을 다음에 재할당할 청크의 주소로 간주하기 때문에 이 원리를 이용하면 임의의 주소에 청크를 할당 할 수 있음

### fastbin duplication with safe linking
safe linking이 적용된 경우 힙 주소를 기반으로 fd에 저장되는 주소 값의 인코딩 디코딩 과정을 거치기 떄문에 실제 익스에 활용하기 위해서는 힙 주소를 릭해야 함, 특히 fastbin duplication을 활용한 공격 기법은 fd를 조작해 fastbin에 fake chunk를 추가하는 방식으로 공격이 이루어지기 때문에 2.32이상에서는 fd를 인코딩해 주는 과정이 필요함 아래 코드는 malloc/malloc.c에 정의된 포인터 인코딩/ 디코딩 매크로 함수임

#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)

실제로 해제된 청크의 메모리를 덤프해 보면 아래의 예시와 같이 safe linking이 적용되어 있음을 볼 수 있으므로 fastbin에서 다음에 재할당될 청크의 주소를 임의의 주소로 설정하려면 safe linking 을 고려하여 값을  설정해야 함
pwndbg> x/20gx 0x5555555594c0
0x5555555594c0: 0x0000000000000000      0x0000000000000051
0x5555555594d0: 0x000055500000c049      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000000
0x555555559500: 0x0000000000000000      0x0000000000000000
0x555555559510: 0x0000000000000000      0x0000000000000051
0x555555559520: 0x000055500000c199      0x0000000000000000
0x555555559530: 0x0000000000000000      0x0000000000000000
0x555555559540: 0x0000000000000000      0x0000000000000000
0x555555559550: 0x0000000000000000      0x0000000000000000

### fake chunk 헤더 설정하기
tcache와 다르게 fastbin은 해제된 청크를 재할당할 떄 청크의 크기가 올바른지 확인하는 과정을 거침
일반적으로 청크의 크기는 헤더에 저장되므로 본 공격 기법으로 임의 위치에 청크를 할당하기 위해선 할당할 위치의 메모리보다 0x8낮은 주소에 faske chunk헤더를 설정하는 과정이 선행되어야 함

아래 코드는 malloc/ malloc.c 에 정의된 _int_malloc()의 일부로 14행에서 chunksize()를 호출해 청크의 크기를 확인한 뒤 15행의 조건문에서 올바른 fastbin 인덱스에 속하는지 검증함 만약 크기가 올바르지 않다면 오류 메시지와 함께 프로그램을 abort시킴
static void *
_int_malloc (mstate av, size_t bytes)
{
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
  {
    idx = fastbin_index (nb);
    mfastbinptr *fb = &fastbin (av, idx);
    ...
    if (victim != NULL)
    {
      ...
      if (__glibc_likely (victim != NULL))
      {
        size_t victim_idx = fastbin_index (chunksize (victim));
        if (__builtin_expect (victim_idx != idx, 0))
    	  malloc_printerr ("malloc(): memory corruption (fast)");
      ...

# 분석
// Name: fastbin_duplication.c 
// Compile: gcc -o fastbin_duplication fastbin_duplication.c 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define SIZE 0x40

char* ptr[3];

void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

void win() {
    execve("/bin/sh", 0, 0);
}

int main() {
    int pos, idx;
    unsigned long target[10];
    long long val = 0xdeadbeef;

    init();

    target[1] = 0x50;
    printf("target: %p\n", target + 2);

    while(1) {
        printf(">> ");
        scanf("%d", &pos);

        switch(pos) {
            case 1: // allocate
                printf("idx: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < 3){
                    ptr[idx] = calloc(1, SIZE);
                    printf("content: ");
                    read(0, ptr[idx], SIZE);
                }
                break;

            case 2: // free
                printf("idx: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < 3)
                    free(ptr[idx]);
                break;
            
            case 3: // view
                printf("idx: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < 3)
                    printf("%s\n", ptr[idx]);
                break;

            case 0:
                if (memcmp((const char *) &target[2], &val, 4) == 0) win();
                return 0;
        }
    }
}

예제 코드는 청크를 할당하고 값을 입력하거나 청크를 해제하거나 청크의 데이터를 출력하는 기능을 제공함 또한 프로그램 종료시 target[2]의 하위 4바이트가 0xdeadbeef라면 win함수를 호출 할 수 있음
case 2: 부분을 살펴보면 청크를 해제한 뒤 포인터를 초기화하지 않기 떄문에 허상 포인터(dangling pointer)가 남음 즉, 이미 해제된 청크를 다시 해제할 수 있는 취약점이 존재함
나아가 이를 이용해 case 3: 으로 이미 해제된 청크의 값을 출력할 수도 있기 때문에 fd의 값을 릭할 수 있음

본 바이너리에는 safe linking 이 적용되어 있어 fd에는 이전에 해제된 청크의 주소가 인코딩된 값이 들어 있으므로 이를 디코딩하면 힙 주소를 알아낼수 있음 이를 통해 safe linking이 적용된 target 주소를 올바르게 인코딩 한다면 우리가 할당하고자 하는 주소인 target [2]에 청크를 할당 할 수있음

따라서 먼저 tcache 를 모두 채운 뒤 두개의 청크를 번갈아 해제하면 fastbin duplication을 일으킴 이후 fd가 가리키는 주소를 조작하면 free list에 target의 주소를 삽입할 수 있음, 이후 청크를 할당받으면 &target[2]의 위치에 데이터를 작성할 수 있으며 해당 위치에 0xdeadbeef를 작성하면 셸을 획득할 수 있음 이때 코드의 30행을 보면 해당 위치에 0xdeadbeef를 작성하면 셸을 획득할 수 있음
이떄 30행을 보면 fake chunk헤더를 사전에 설정해 두었기 떄문에 청크 헤더를 구성하는 것은 고려하지 않아도 됨

## 익스 설계
63행의 조건문을 만족시켜 win함수를 실행해야 함 본문제는 메모리 할당 시 calloc()을 사용하기 떄문에 fastbin duplication으로 target에 청크를 할당하고 target[2]의 값을 0xdeadbeef로 조작하면 문제를 해결할 수 있을것임 즉, 힙 주소를 릭해 target의 주소를 올바르게 인코딩한 뒤 스택에 청크를 할당 받고 데이터를 조작해야 함

1. fastbin duplication 트리거
메모리를 할당 할떄 calloc을 사용하기 때문에 tcache 와 관련된 공격기법을 사용하기 어려우므로 fastbin duplication을 사용해 스택에 존재하는 target을 free list에 추가하면 힙이 아닌 스택 영역에 메모리를 할당 받을수 있을거임 앞서 살펴봤듯 fastbin은 서로 다른 청크를 번갈아 해제하는 방식으로 관련 보호 기법을 우회할 수 있음
2. safe linking 우회
힙 주소를 릭 한뒤 safe linking이 적용된 값으로 포인터를 조작해야 의도한 주소에 청크를 할당받을수 있음 본 문제에서는 case 3: 을 통해 fd의 값을 릭할 수 있으므로 해당 값을 통해 힙 주소를 알아내고 safe linking 을 우회할 수 있음
3. target위치에 청크 할당
포인터를 올바르게 조작한 두에는 조작된 fastbin을 이용해 스택에 메모리를 할당 받아야 함 할당을 받은 뒤 값으로 0xdeadbeef를 입력하고 프로그램을 종료하면 셸을 획득 가능

### 요약
fastbin은 tcache로 뚫기 힘드니 tcache를 7개를 다 채우고 fastbin으로 넘어가고
fastbin은 단일 연결 리스트이므로 임의로 할당을 2개를 하고 그 후 번갈아가면서 free하면 double free가 가능해짐
그후 해당 문제에서는 safe linking이 존재하므로 safe linking 인코딩을 하기 위해 view를 들어가서 임의의 메모리를 릭하고 해당 릭한 주소를 leak ^ leak >> 12 ^ leak >>24 ^ leak >>36 으로 쉬프트 연산을 하고 fake addr이 존재하니 target에서 -0x10을하고 그후 아까 구한 leak한 주소를 addr>>12로 쉬프트 연산을 하고 xor을 해주면  우리가 원하는 주소로 변경이 가능함

그후 다시 대 할당을 해서 next를 addr로 바꾸고 그후 8byte + 8byte로 padding을 해주고 0xdeadbeef로 수정하게 하면 됨
그 후 0번을 호출해서 win if문을 넘어가면 됨