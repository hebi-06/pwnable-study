# _IO_file
모든 파일 함수는 fopen 함수에서 반환한 파일 포인터를 인자로 전달 받고 기능을 수행하기에 앞서 파일 포인터를 참조해 파일 정보를 먼저 확인함 파일의 정보로는 파일이 어떤 모드로 열렸으며 파일 작업을 수행하기 위한 함수의 주소가 포함됨에 따라 파일 작업이 어떻게 이뤄지는지 알기 위해서는 파일 구조체를 이해하고 있어야 함

## 배경 지식
// Name: iofile.c
// Compile: gcc -o iofile iofile.c

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void file_info(FILE *buf) {
  printf("_flags: %x\n", buf->_flags);
  printf("_fileno: %d", buf->_fileno);
}

int main() {
  FILE *fp;
  char buf[256];
  strcpy(buf, "THIS IS TESTFILE!");
  fp = fopen("testfile", "w");
  fwrite(buf, 1, strlen(buf), fp);

  file_info(fp);

  fclose(fp);
  return 0;
}

우분투 18.04 버전

_IO_FILE은 리눅스 시스템의 표준 라이브러리에서 파일 스트림을 나타내기 위한 구조체임 이는 파일을 열기 위한 fopen 함수를 사용할때 힙 영역에 할당됨
아래는 _IO_FILE파일 구조체이며 표에서 중요 멤버 변수에 대한 설명을 확인 가능
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};

struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

_flags  파일에 대한 읽기/쓰기 추가 권한을 의미, 0x7bad0000값을 매직 값으로 하위 2바이트는 비트 플래그로 사용됨
_IO_read_ptr    파일 읽기 버퍼에 대한 포인터
_IO_read_end    파일 읽기 버퍼 주소의 끝을 가리키는 포인터
_IO_read_base   파일 읽기 버퍼 주소의 시작을 가리키는 포인터
_IO_write_base  파일 쓰기 버퍼 주소의 시작을 가리키는 포인터
_IO_write_ptr   쓰기 버퍼에 대한 포인터
_IO_write_end   파일 쓰기 버퍼 주소의 끝을 가리키는 포인터
_chain  프로세스의 _IO_FILE 구조체는 _chain필드를 통해 리크드 리스트를 만듬 링크드 리스트의 헤더는 라이브러리의 전역 변수인 _IO_list_all 에 저장됨
_fileno 파일 디스크립터의 값
_IO_jump_t *vtable  파일 관련 작업을 수행하는 가상 함수 테이블

### _IO_FILE: _flags
_flags 멤버 변수는 파일의 성질을 나타내는 필드
해당 필드는 fopen 함수로 파일을 열때 전달한 모드에 따라 값이 설정됨 아래는 _flags 변수를 구헝하는 각 비트들의 집합임
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000

예제 코드를 컴파일하고 실행해보면 다음과 같은 결과가 출력되는데 0xfbad2c84는 _IO_MAGIC이라는 매직 넘버를 포함한 각 권한을 의미 해당 값은 _IO_MAGIC, _IO_NO_READS, _IO_LINKED, _IO_TIED_PUT_GET, _IO_CURRNTLY_PUTTING, _IO_IS_FILEBUF 비트가 포함된 것을 알 수 있음
$ ./iofile
_flags: fbad2c84
_fileno: 3


앞서 _flags 멤버 변수는 fopen 함수로 파일을 열때 전달한 모드에 따라 값이 설정된다고 했음 아래 코드는 fopen함수가 호출될때 실행되는 내부 함수인 _IO_new_file_fopen임 코드를 살펴보면 fopen 함수의 두번째 인자인 mode 변수가 r, w, a문자인지 확인하고 각 권한에 해당하는 비트가 할당되는 것을 확인 가능
FILE *_IO_new_file_fopen(FILE *fp, const char *filename, const char *mode,
                         int is32not64) {
  int oflags = 0, omode;
  int read_write;
  int oprot = 0666;
  int i;
  FILE *result;
  const char *cs;
  const char *last_recognized;
  if (_IO_file_is_open(fp)) return 0;
  switch (*mode) {
    case 'r':
      omode = O_RDONLY;
      read_write = _IO_NO_WRITES;
      break;
    case 'w':
      omode = O_WRONLY;
      oflags = O_CREAT | O_TRUNC;
      read_write = _IO_NO_READS;
      break;
    case 'a':
      omode = O_WRONLY;
      oflags = O_CREAT | O_APPEND;
      read_write = _IO_NO_READS | _IO_IS_APPENDING;
      break;
      ...
  }


  더 자세히 살펴보면 read_write 뿐만 아니라 omode 변수에 O_RDONLY, O_WRONLY등의 값이 저장되는 것을 볼 수 있음 fopen함수는 결국 open시스템 콜을 호출해 파일을 열게 되는데 이떄 해당 시스템 콜의 인자로 전달됨


### _IO_FILE: vtable
앞서 _IO_FILE 구조체가 포함된 _IO_FILE_plus 구조체를 살펴보면 vtable 포인터가 존재하는 것을 확인 가능 virtual function Table(vtable)은 객체 지향 프로그래밍 언어에서 클래스를 정의하고 가상 함수를 사용할 때 할당되는 테이블임 이는 메모리에 가상 함수를 담을 영역을 할당하고 함수의 주소를 기록함 가상 함수를 사용하면 해당 테이블을 기준으로 상대 주소를 통해 호출함

파일 구조체는 각 파일 마다 _IO_FILE구조체 뿐만 아니라 함수 테이블을 가지고 있음 vtable 변수는 객체 지향 프로그래밍에서 사용하는 테이블과 비슷하게 구현되어 있으며 파일 함수를 호출하면 해당 테이블을 참조하고 실제 기능을 수행하는 함수를 호출함

아래는 파일 함수의 테이블을 정의한 _IO_jump_t구조체의 모습임
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};

구조체를 살펴보면 16바이트 크기의 더미 바이트를 포함해 다양한 함수가 정의된 것을 확인 할 수 있음 또한, 아래 코드는 디버깅을 통해 fopen 함수로부터 반환된 파일 포인터의 vtable 모습을 확인한 결과임
gdb-peda$ p *(struct _IO_jump_t *)0x00007ffff7dca2a0
$32 = {
  __dummy = 0x0, 
  __dummy2 = 0x0, 
  __finish = 0x7ffff7a6e400 <_IO_new_file_finish>, 
  __overflow = 0x7ffff7a6f3d0 <_IO_new_file_overflow>, 
  __underflow = 0x7ffff7a6f0f0 <_IO_new_file_underflow>, 
  __uflow = 0x7ffff7a70490 <__GI__IO_default_uflow>, 
  __pbackfail = 0x7ffff7a71d20 <__GI__IO_default_pbackfail>, 
  __xsputn = 0x7ffff7a6da00 <_IO_new_file_xsputn>, 
  __xsgetn = 0x7ffff7a6d660 <__GI__IO_file_xsgetn>, 
  __seekoff = 0x7ffff7a6cc60 <_IO_new_file_seekoff>, 
  __seekpos = 0x7ffff7a70a60 <_IO_default_seekpos>, 
  __setbuf = 0x7ffff7a6c920 <_IO_new_file_setbuf>, 
  __sync = 0x7ffff7a6c7a0 <_IO_new_file_sync>, 
  __doallocate = 0x7ffff7a601e0 <__GI__IO_file_doallocate>, 
  __read = 0x7ffff7a6d9e0 <__GI__IO_file_read>, 
  __write = 0x7ffff7a6d260 <_IO_new_file_write>, 
  __seek = 0x7ffff7a6c9e0 <__GI__IO_file_seek>, 
  __close = 0x7ffff7a6c910 <__GI__IO_file_close>, 
  __stat = 0x7ffff7a6d250 <__GI__IO_file_stat>, 
  __showmanyc = 0x7ffff7a71ea0 <_IO_default_showmanyc>, 
  __imbue = 0x7ffff7a71eb0 <_IO_default_imbue>
}

#### _IO_FILE: vtable 호출 과정
_IO_jump_t구조체에 어떻게 접근하는지 알아보기 위해 fread함수의 호출 과정을 코드로 따라가보면
아래 코드를 살펴보면 fread함수는 _IO_fread 함수와 동일하게 정의된 것을 볼 수 있으며 해당 함수 내부에서 _IO_sgetn함수를 호출함
#define fread(p, m, n, s) _IO_fread (p, m, n, s)
size_t
_IO_fread (void *buf, size_t size, size_t count, FILE *fp)
{
  size_t bytes_requested = size * count;
  size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}

또한 아래는 _IO_sgetn함수의 구현체로 _IO_XSGETN을 호출함 코드의 상단에서 정의된 매크로를 순차적으로 확인해보면 결국 앞서 살펴본 vtable 변수를 참조하는 것을 확인 할 수 있음

#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
#define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable ( (THIS)))
size_t
_IO_sgetn (FILE *fp, void *data, size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);
}

fread를 포함한 모든 파일 함수는 이처럼 가상 함수 테이블을 참조해 파일 작업을 시도함 그러나 해당 함수 테이블은 동적으로 할당되는 영역으로 쓰기 권한이 있기 때문에 공격에 악용될수 있음

## 요약
_IO_FILE: 리눅스 시스템의 표준 라이브러리에서 파일 스트림을 나타내기 위한 구조체
Virtual function Table(vtable): 객체 지향 프로그래밍 언어에서 클래스를 정의하고 가상 함수를 사용할 떄 할당되는 테이블
