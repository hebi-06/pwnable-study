# 코드 분석
## 보호기법
$ pwn checksec iofile_aaw
[*] 'iofile_aaw'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)


## 코드분석
예제에서는 /etc/issue 파일을 열고 파일 포인터에 300바이트 만큼의 값을 입력할 수 있음
이후 fread함수를 통해 파일의 내용을 읽고 출력함
이때, 전역 변수인 overwrite_me 변수의 값이 0xDEADBEEF라면 read_flag함수를 호출해 flag 파일을 읽고 종료함
'''
// Name: iofile_aaw
// gcc -o iofile_aaw iofile_aaw.c -no-pie

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char flag_buf[1024];
int overwrite_me;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int read_flag() {
  FILE *fp;
  fp = fopen("/home/iofile_aaw/flag", "r");
  fread(flag_buf, sizeof(char), sizeof(flag_buf), fp);

  write(1, flag_buf, sizeof(flag_buf));
  fclose(fp);
}

int main() {
  FILE *fp;

  char file_buf[1024];

  init();

  fp = fopen("/etc/issue", "r");

  printf("Data: ");

  read(0, fp, 300);

  fread(file_buf, 1, sizeof(file_buf)-1, fp);

  printf("%s", file_buf);

  if( overwrite_me == 0xDEADBEEF)
    read_flag();

  fclose(fp);
}
'''

#익스 
익스의 목표는 fread함수에서 참조하는 파일 구조체를 조작해 전역 변수 overwrite_me 의 값을 0xDEADBEEF로 덮어쓰고 flag를 얻는 것임

## 1. 파일 구조체 조작
임의 주소에 값을 쓰기 위해서는 _IO_buf_end와 _IO_buf_base를 조작해야 함
파일의 내용을 읽을때 아래와 같은 코드가 실행되므로 _IO_buf_base를 overwrite_me의 주소로 조작하고 _IO_buf_end를 overwrite_me주소에 1024보다 큰 수를 더한 값으로 조작함
1024보다 큰 숫자를 더하는 이유는 _IO_new_file_underflow 코드내에서 _IO_buf_end - _IO_buf_base 값이 fread함수의 인자로 전달된 읽을 크기보다 커야하는 조건이 있기 때문임 
해당 조건을 만족했다면 이와 동시에 /etc/issu 로부터 데이터를 읽는 것이 아닌 '표준 입력을 통해 값을 전달하기 위해 _fileno 즉 파일 디스크립터 번호로 stdin을 나타내는 0으로 덮으면 됨'
read(f->_fileno, _IO_buf_base, _IO_buf_end - _IO_buf_base);


코드를 살펴보면 overwrite_me에 값을 쓰기 위해 _IO_buf_base와 _IO_buf_end에 각각 overwrite_me주소와 overwrite+1024의 주소를 입력함

값을 덮어쓰기 위한 과정을 마치면 프로그램에서 표준 입력을 사용해 값을 입력할 수 있도록 _fileeno를 0으로 변경해야 함