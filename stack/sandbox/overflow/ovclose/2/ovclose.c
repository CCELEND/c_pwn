//gcc -o ovclose ovclose.c -lseccomp
//Ubuntu18
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int buf[0x50];

void init() {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0LL); //禁用 execve
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0LL); //禁用 execveat
	seccomp_load(ctx);
	setvbuf(stdin,  0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
}

int main(){
	init();
	char data[0x40];
	unsigned long long cookie,MysteriousXOR;
	puts("Enter your name:");
	read(0, data, 0x40uLL);
	printf("Hello %s\n", data);

	puts("Enter your cookie:");
	scanf("%llu",&cookie);
	MysteriousXOR = (unsigned long long)&buf^0x15CC15CC15CC15CC;
	if(cookie != MysteriousXOR){
		puts("What a damn sham :(");
		_exit(0);
	}
	puts("correct cookie :)");
	puts("Enter your favorite sentence:");
	read(0, data, 0x49uLL);
	printf("Wow: %s\n", data);
	
	puts("I won't be able to see anything in the future :(");
	close(1);
	read(0, data, 0x60uLL);
	return 0;
}
