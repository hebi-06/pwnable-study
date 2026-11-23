// Format String Bug → GOT overwrite 예제 (Partial RELRO, No-PIE)
// 컴파일: gcc -no-pie -fcf-protection=none -o vuln vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() { system("/bin/sh"); }

int main() {
    char buf[0x80];
    setvbuf(stdout, 0, _IONBF, 0);
    read(0, buf, 0x80);
    printf(buf);              // ← 포맷스트링 버그
    puts("");
    exit(0);                 // ← exit@got를 win으로 덮으면 여기서 트리거
}
