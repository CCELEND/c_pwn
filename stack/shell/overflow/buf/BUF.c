//gcc -o BUF BUF.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void init(){
    setvbuf(stdin,  0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void login(){
	char name[16];
    printf("Enter your name: \n");
	read(0, name, 8uLL);
	printf("Hello %s\n", name);	
}

void vuln(){
    char buf[100];
    for(int i = 0; i < 2; i++){
        printf("Enter your data:\n");
        read(0, buf, 0x200); //栈溢出
        printf("Your data: %s\n", buf);
    }
}

int main(){
    init();
    login();
    printf("Please pwn me :)\n");
    vuln();
    return 0;
}


