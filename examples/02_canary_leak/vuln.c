// 카나리 leak 예제: Canary 켜짐, No-PIE
// 컴파일: gcc -no-pie -fcf-protection=none -o vuln vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() { system("/bin/sh"); }

void vuln() {
    char buf[0x40];
    puts("step1: send name");
    read(0, buf, 0x49);            // 0x40 + 카나리 LSB까지 딱 1바이트 더
    printf("hello %s\n", buf);     // buf를 %s로 출력 → \x00 덮으면 카나리 샘
    puts("step2: send payload");
    read(0, buf, 0x100);           // 이번엔 크게 오버플로우
}

int main() {
    setvbuf(stdout, 0, _IONBF, 0);
    vuln();
    return 0;
}
