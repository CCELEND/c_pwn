//gcc -z now -fno-stack-protector -no-pie -o ret2shellcode ret2shellcode.c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

char buf1[100];

int main(void)
{
    mprotect((int)buf1&~0xfff, 0x1000, 0x7);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 1, 0LL);
    char buf[100];
    printf("Please pwn me :)\n");
    gets(buf);
    strncpy(buf1, buf, 100);
    return 0;
}
