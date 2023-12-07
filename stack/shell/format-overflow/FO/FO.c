//gcc -no-pie -o FO FO.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void getshell(void) {
    system("/bin/sh");
}

void init() {
    setvbuf(stdin,  0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

int main(){
    init();
    char buf[0x20];
    printf("Please pwn me :)\n");
    read(0, buf, 0x38);
    printf(buf);
    return 0;
}


