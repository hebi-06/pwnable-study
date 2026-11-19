// gcc main.c -o main -z relro -z now
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

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
    size_t *addr;
    size_t value;

    init();

    printf("[libc GOT Overwrite]\n");

    printf("stdout: %p\n", stdout);
    printf("win: %p\n", win);
    printf("Address: ");
    scanf("%zu", (size_t *) &addr);
    printf("Value: ");
    scanf("%zu", &value);
    *addr = value;
    printf("Overwrite Done!\n");
}