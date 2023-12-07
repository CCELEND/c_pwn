//gcc -fno-stack-protector -z now -no-pie -o stack-migration stack-migration.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void getshell(void)
{
    system("no binsh!");
}

int main(void)
{ 
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin,  0LL, 2, 0LL);
    char buf[0x20];
    printf("Here's your gift: %p\n", buf);
    printf("Please pwn me :)\n");
    read(0, buf, 0x30);
    return 0;
}
