//gcc close.c -o close
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init() {
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

int main(){
	init();
	char data[2056];
	login();
	printf("Here's your gift: %p\n", data);
    printf("Please pwn me :)\n");
    close(1);
    read(0, data, 0x200uLL);
    //dup2(2,1);
    printf(data);
    return 0;
}
