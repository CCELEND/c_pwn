//gcc -fno-stack-protector -z now -no-pie -o ret2libc2 ret2libc2.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char buf1[100];

void getshell(void)
{
    system("no binsh!");
}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 1, 0LL);
    char buf[100];
    printf("Please pwn me :)\n");
    gets(buf);
    return 0;
}
