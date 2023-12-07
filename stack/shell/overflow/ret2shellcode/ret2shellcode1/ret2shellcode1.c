//gcc -z now -fno-stack-protector -o ret2shellcode1 ret2shellcode1.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void)
{
	mmap((void *)0x123000, 0x1000, 7, 34, -1, 0);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 1, 0LL);
    char buf[100];
    printf("Please pwn me :)\n");
    read(0, buf, 0x100);
    strncpy((char *)0x123000, buf, 0x100);
    return 0;
}
