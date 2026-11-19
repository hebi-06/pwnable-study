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