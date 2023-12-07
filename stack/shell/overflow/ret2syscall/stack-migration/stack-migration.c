//gcc -static -fno-stack-protector -z now -no-pie -o stack-migration stack-migration.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char *shell = "/bin/sh";
char buf1[100];

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 1, 0LL);
    char buf[8];
    printf("Please pwn me :)\n");
    read(0, buf1, 100);
    printf("Enter your name: \n");
    read(0, buf, 30);
    return 0;
}
