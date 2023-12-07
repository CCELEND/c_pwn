//gcc -o FORMAT FORMAT.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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
    read(0, data, 0x200uLL);
    printf(data);
    return 0;
}