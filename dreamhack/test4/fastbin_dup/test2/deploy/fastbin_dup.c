// Name: fastbin_dup.c 
// Comppile: gcc -o fastbin_dup fastbin_dup.c -no-pie -fno-stack-protector

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
    char name[16];
    int pos, idx, size;

    init();

    printf("name? ");
    read(0, name, 16);

    printf("Hi, %s", name);
    printf("The name was written at memory %p.\n", name);

    while(1) {
        printf(">> ");
        scanf("%d", &pos);

        switch(pos) {
            case 1: // allocate
                printf("idx: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < 3){
                    printf("size: ");
                    scanf("%d", &size);
                    ptr[idx] = calloc(1, size);
                    printf("content: ");
                    read(0, ptr[idx], size);
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
                return 0;
                    
        }
    }
}