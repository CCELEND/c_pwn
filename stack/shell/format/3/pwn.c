//gcc -fstack-protector-all -o pwn pwn.c 
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
	int i;
	unsigned int size;
	void *size_4;
	char s[8];
	for(i = 0; i < 3; i++)
	{
		printf("Please input the length: ");
		memset(s, 0, sizeof(s));
		read(0, s, 4uLL);
		size = atoi(s);
		if ( size <= 500 )
		{
			size_4 = realloc(size_4, size);
			if ( size )
			{
				printf("Please input the content: ");
				read(0, size_4, size);
				printf((const char *)size_4);
			}
		}
	}
	_exit(0);
}