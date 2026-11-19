# _IO_FILE Arbitrary address write
glibc 2.27을 탑재한 18.04 환경 기준으로 함
'''
// Name: iofile_aaw.c
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

# docker 구축
$ CONTAINER_NAME=my_container; \
docker build . -t ubuntu1804; \
docker run -d -t --privileged --name=$CONTAINER_NAME ubuntu1804; \
docker exec -it -u root $CONTAINER_NAME bash

## 파일 읽기 함수 분석
### 파일 읽기 과정
파일의 내용을 읽기 위한 함수는 대표적으로 fread, fgets가 있음
해당 함수는 라이브러리 내부에서 _IO_file_xsgetn함수를 호출함 아래 코드를 살펴보면 해당 함수는 파일 함수의 인자로 전달된 n이 _IO_buf_end - _IO_buf_base값보다 작은지를 검사함 이는 즉 _underflow, _IO_new_file_underflow함수를 호출함
'''
_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  _IO_size_t want, have;
  _IO_ssize_t count;
  _char *s = data;
  want = n;
    ...
	  /* If we now want less than a buffer, underflow and repeat
	     the copy.  Otherwise, _IO_SYSREAD directly to
	     the user buffer. */
	  if (fp->_IO_buf_base
	      && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
	    {
	      if (__underflow (fp) == EOF)
		break;

	      continue;
	    }
	...
}
'''

### _IO_new_file_underflow 
아래코드는 _IO_new_file_underflow 함수로 코드를 살펴보면 해당 함수 내부에서는 파일 포인터의 _flags 변수에 읽기 권한이 부여되어 있는 것을 확인 할 수 있으며 이후 _IO_SYSREAD함수의 인자로 파일 포인터와 파일 구조체의 멤버 변수를 연산한 값이 전달됨
'''
int _IO_new_file_underflow (FILE *fp)
{
  ssize_t count;
  if (fp->_flags & _IO_NO_READS)           
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
   ...
   count = _IO_SYSREAD (fp, fp->_IO_buf_base,     
	fp->_IO_buf_end - fp->_IO_buf_base);
}
'''
_IO_SYSREAD함수는 vtable의 _IO_file_read함수로 아래 매크로에서 확인 가능
'''
#define _IO_SYSREAD(FP, DATA, LEN) JUMP2 (__read, FP, DATA, LEN)
'''

### _IO_file_read
_IO_file_read함수 내부에서는 read시스템 콜을 사용해 파일의 데이터를 읽음 
시스템 콜의 인자로 파일 구조체에서 파일 디스크립터를 나타내는 _fileno, _IO_buf_base인 buf 그리고 _IO_buf_end - _IO-buf_base로 연산된 size 변수가 전달됨
'''
_IO_ssize_t
_IO_file_read (_IO_FILE *fp, void *buf, _IO_ssize_t size)
{
  return (__builtin_expect (fp->_flags2 & _IO_FLAGS2_NOTCANCEL, 0)
	  ? __read_nocancel (fp->_fileno, buf, size)
	  : __read (fp->_fileno, buf, size));
}
'''
전달되는 인자를 파일 구조체로 표현하면 다음과 같음
'''
read(f->_fileno, _IO_buf_base, _IO_buf_end - _IO_buf_base);
'''

