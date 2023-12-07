//gcc -z now -fno-stack-protector -no-pie -o ret2shellcode2 ret2shellcode2.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

char buf1[0x30];

int main(void)
{
	mmap((void *)0x123000, 0x1000, 7, 34, -1, 0);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 1, 0LL);
    char buf[0x20];
    printf("Please pwn me :)\n");
    read(0, buf, 0x30);
    memcpy(buf1, buf, 0x30);
    return 0;
}
