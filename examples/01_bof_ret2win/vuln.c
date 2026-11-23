// BOF ret2win 예제: 카나리 없음, NX, No-PIE
// 컴파일: gcc -fno-stack-protector -no-pie -o vuln vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {                       // 이 함수로 리턴을 돌리는 게 목표
    puts("[win] you got the shell!");
    system("/bin/sh");
}

void vuln() {
    char buf[0x30];                // 0x30짜리 버퍼
    puts("overflow me:");
    read(0, buf, 0x100);           // 0x100까지 읽음 → 오버플로우
}

int main() {
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    vuln();
    return 0;
}
