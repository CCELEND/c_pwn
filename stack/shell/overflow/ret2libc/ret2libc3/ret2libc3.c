//gcc -fno-stack-protector -z now -no-pie -o ret2libc3 ret2libc3.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void getshell(void)
{
    int secretcode, input;
    srand(time(NULL));
    secretcode = rand();
    scanf("%d", &input);
    if(input == secretcode)
        puts("no system!");
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
