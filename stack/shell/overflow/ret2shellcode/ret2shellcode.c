//gcc -z now -fno-stack-protector -z execstack -o ret2shellcode ret2shellcode.c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

int main(void)
{
	mmap((void *)0x123000, 0x1000, 7, 34, -1, 0);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 1, 0LL);
    char buf[100];
    printf("Please pwn me :)\n");
    gets(buf);
    strncpy((char *)0x123000, buf, 100);
    return 0;
}
