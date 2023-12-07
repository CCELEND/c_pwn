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

int main(){
	init();
	char data[2056];
	printf("Please pwn me :)\n");
	for(int i = 0; i < 2; i++){
		printf("Enter your data:\n");
        read(0, data, 0x200uLL);
    	printf(data); //格式化字符串
	}
    return 0;
}