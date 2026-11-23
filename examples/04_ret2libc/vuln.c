// ret2libc 예제: NX, No Canary, No-PIE, 동적링크
// 컴파일: gcc -fno-stack-protector -no-pie -fcf-protection=none -o vuln vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 최신 gcc/glibc(2.34+)엔 __libc_csu_init 가젯이 없어, 교육용으로 심어둔 가젯.
// (실제 문제에선 libc 안의 'pop rdi; ret'을 찾아 씀)
__attribute__((used)) void gadget() { asm volatile("pop %rdi; ret"); }

void vuln() {
    char buf[0x40];
    read(0, buf, 0x100);
}

int main() {
    setvbuf(stdout, 0, _IONBF, 0);
    puts("go");
    vuln();
    vuln();
    return 0;
}
