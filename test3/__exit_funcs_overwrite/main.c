// gcc main.c -o main -z relro -z now
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <errno.h>


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