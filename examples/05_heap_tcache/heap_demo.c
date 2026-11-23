// gdb로 힙 구조 관찰용 데모. break breakpoint_here 후 heap/tcachebins/bins 확인
#include <stdlib.h>
#include <string.h>
void breakpoint_here() {}
int main() {
    char *a = malloc(0x30); strcpy(a, "AAAAAAAA");   // tcache 0x40 bin
    char *b = malloc(0x30); strcpy(b, "BBBBBBBB");
    char *c = malloc(0x30);
    char *big = malloc(0x500);                        // unsorted 유도용
    malloc(0x20);                                     // top 병합 방지 guard
    free(a); free(b);          // tcache[0x40]에 b→a 순으로 2개
    free(big);                 // 0x510 → unsorted bin (fd/bk = libc)
    breakpoint_here();
    return 0;
}
