//gcc -o BUF BUF.c 
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

void vuln(){
    char buf[100];
    for(int i = 0; i < 2; i++){
        printf("Enter your data:\n");
        read(0, buf, 0x200); //栈溢出
        printf(buf); //格式化字符串
    }
}

int main(){
    init();
    printf("Please pwn me :)\n");
    vuln();
    return 0;
}


