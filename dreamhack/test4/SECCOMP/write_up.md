# SECCOMP
## 코드
// gcc -o seccomp seccomp.cq
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <sys/mman.h>

int mode = SECCOMP_MODE_STRICT;

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int syscall_filter() {
    #define syscall_nr (offsetof(struct seccomp_data, nr))
    #define arch_nr (offsetof(struct seccomp_data, arch))
    
    /* architecture x86_64 */
    #define REG_SYSCALL REG_RAX
    #define ARCH_NR AUDIT_ARCH_X86_64
    struct sock_filter filter[] = {
        /* Validate architecture. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
        /* Get system call number. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
        };
    
    struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter,
        };
    if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
        return -1;
        }
    
    if ( prctl(PR_SET_SECCOMP, mode, &prog) == -1 ) {
        perror("Seccomp filter error\n");
        return -1;
        }
    return 0;
}


int main(int argc, char* argv[])
{
    void (*sc)();
    unsigned char *shellcode;
    int cnt = 0;
    int idx;
    long addr;
    long value;

    initialize();

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while(1) {
        printf("1. Read shellcode\n");
        printf("2. Execute shellcode\n");
        printf("3. Write address\n");
        printf("> ");

        scanf("%d", &idx);

        switch(idx) {
            case 1:
                if(cnt != 0) {
                    exit(0);
                }

                syscall_filter();
                printf("shellcode: ");
                read(0, shellcode, 1024);
                cnt++;
                break;
            case 2:
                sc = (void *)shellcode;
                sc();
                break;
            case 3:
                printf("addr: ");
                scanf("%ld", &addr);
                printf("value: ");
                scanf("%ld", addr);
                break;
            default:
                break;
        }
    }
    return 0;
}



- 분석

프로그램은 실행 가ㅏ능한 메모리를 mmap()으로 할당한 뒤 메뉴를 통해 다음 기능을 제공함

1. syscall_filter()를 호출해 SECCPM{를 설정하고 셸코드를 입력함
2. 1에서 입력한 셸코드를 실행함
3. 임의 주소 쓰기를 수행함

다음 토픽은 syscall_filter()분석

프로그램이 셸코드를 입력하고 실행하는 기능과 임의 주소 쓰기 기능을 제공한다는 점을 확인했는대
이제 syscall_filter()를 살펴보면 전역 변수 mode가 SECCOMP설정에 어떤 영향을 주 분석

첫번째 prctl()은 PR_SET_NO_NEW_PRIVS를 설정함 이설정은 프로세스가 execvee()등을 통해 현재보다 높은 권한을 얻지 못하게 하며 권한이 없는 프로세스가 FILTER모드를 적용하기 위한 조건임

두번째 prctl()은 실제로 SCCOMP를 설정함 두번쨰 인자인 mode는 적용할 모드를 결정하고 세번쨰 인자인 &prog는 FILTET모드에서 사용할 cBPF 프로그램을 가리킴

전역 변수 mode의 초기값은 SECCOMP_MODE_STRICT임
int mode = SECCOMP_MODE_STRICT;
STRICT모드가 적용되면 프로세스는 read, write, _exit, sigreturn 등 제한된 시스템 콜만 사용할 수 있음 따라서 execve()를 호추하면 프로세스가 종료됨

반면 mode를 SECCOMP_MODE_FILTER로 바꾸면 커널은 &prog가 가리키는 cBPF프로그램을  검사하고 각 시스템 콜에 적용할 동작을 결정함


### cBPF 필터 분석
#define ARCH_NR AUDIT_ARCH_X86_64
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
};
순서    동작
1. 현재 시스템 콜의 아키텍처 식별값을 읽음
2. 아키텍처가 x86-64인지 확인함
3. x86-64가 아니면 SECCOMP_RET_KILL을 반환함
4. x86-64라면 시스템 콜 번호를 읽음

해당 필터는 정상적으로 동작하지 않기 때문에 익스 과정에서 이용할 수 있음 FILTER모드의 cBPF프로그램은 모든 실행 경로에서 SECCOMP_RET_ALLOW, SECCOMP_RET_KILL과 같은 동작을 반환해야 함 그러나 이 필터는 시스템 콜 번호만 읽은 뒤 종료하므로 커널은 이 필터를 유효하지 않은 프로그램으로 판단하여 설치를 거부함

따라서 mode가 FILTER로 바뀐 상태에서 syscall_filter()를 호출하면 필터가 정상적으로 설치되지 않음
이후 main이 필터의 설치여부를 확인하지 않고 바로 셸코드를 실행하기 때문에 공격자가 execve같은 함수를 사용 가능해짐

## 익스 설계
1. mode 변조
3번째 메큐의 임의 쓰기 취약점으로 전역 변수 mode에 FILTER모드를 뜻하는 값 2를 쓰고
write_address(address of `mode`, 2)
+ PIE가 없어서 mode의 주소는 바이너리엣 ㅓ직접 구하기 가능

2. 필터 설치 실패와 셸코드 입력
첫번째 메뉴를 선택하면 프로그램은 변경된 mode를 사용해 SECCOMP필터를 FILTER모드로 설정함 그러나 전달되는 cBPF프로그램이 유효하지 않으므로 커널은 설치를 거부하게 됨
프로그램을 필터 설치 여부와 관계없이 셸코드를 입력 받기 떄문에 셸코드를 쓰면 됨

3. 셸코드
이제 execve함수가 차단이 아노디서 shellcaft.sh()쓰면 됨

