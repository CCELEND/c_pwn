//gcc -fno-stack-protector -z now -no-pie -o ret2text ret2text.c
#include <stdio.h>
#include <stdlib.h>

void getshell(void)
{
    system("/bin/sh");
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
