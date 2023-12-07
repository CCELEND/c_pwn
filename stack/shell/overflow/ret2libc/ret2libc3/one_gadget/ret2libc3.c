//gcc -fno-stack-protector -o ret2libc3 ret2libc3.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 1, 0LL);
    char buf[0x30];
    printf("Please pwn me :)\n");
    read(0, buf, 0x40);
    return 0;
}
