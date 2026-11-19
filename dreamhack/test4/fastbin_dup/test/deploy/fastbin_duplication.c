// Name: fastbin_duplication.c 
// Comppile: gcc -o fastbin_duplication fastbin_duplication.c 

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