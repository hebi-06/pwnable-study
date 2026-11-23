// gcc main.c -o main -z relro -z now
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
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

void thread_routine() {
    char buf[256];
    int size = 0;
    size_t *addr, *fs_base;

    syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
    printf("fs_base: %p\n", fs_base);

    printf("buf_addr: %p\n", buf);
    printf("win: %p\n", win);
    printf("size: ");
    scanf("%d", &size);
    printf("data: ");
    read(STDIN_FILENO, buf, size);
    exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[])
{
    pthread_t thread_t;

    init();

    printf("[__call_tls_dtors]\n");
    pthread_create(&thread_t, NULL, (void *)thread_routine, NULL);
    pthread_join(thread_t, 0);
}