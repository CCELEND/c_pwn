//gcc -z now -no-pie -o easy easy.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int num;

void init() {
    setvbuf(stdin,  0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

int main(){
    init();
    char data[100];
    printf("Please pwn me :)\n");
    read(0, data, 0x100uLL);
    printf(data);
    if(num == 16)
    {
        system("/bin/sh");
    }
    return 0;
}