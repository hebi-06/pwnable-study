// 힙 UAF → tcache poisoning 예제 (glibc 2.32+ safe-linking 포함)
// 컴파일: gcc -no-pie -fcf-protection=none -o vuln vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *notes[8];
void (*fp)() = 0;              // .bss 함수 포인터. 종료 시 호출됨 → 공격 타깃
void win() { system("/bin/sh"); }

int menu() {
    int c;
    printf("\n1.alloc 2.free 3.edit 4.view 5.exit\n> ");
    if (scanf("%d", &c) != 1) exit(0);
    return c;
}
int idx() { int i; printf("idx> "); scanf("%d", &i); return i & 7; }

int main() {
    setvbuf(stdout, 0, _IONBF, 0);
    while (1) {
        switch (menu()) {
        case 1: {                         // alloc
            int i = idx(); notes[i] = malloc(0x30);
            printf("ok %d\n", i); break;
        }
        case 2: {                         // free (UAF: 포인터 안 지움)
            free(notes[idx()]); puts("freed"); break;
        }
        case 3: {                         // edit (UAF 쓰기 가능)
            int i = idx(); printf("data> ");
            read(0, notes[i], 0x30); break;
        }
        case 4: {                         // view (UAF 읽기 → heap leak)
            int i = idx();
            write(1, notes[i], 8); puts(""); break;
        }
        case 5:
            if (fp) fp();                 // ← 여기로 흐름 탈취
            return 0;
        }
    }
}
