//gcc -fno-stack-protector -o ovclose ovclose.c -lseccomp
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

void login(){
	char name[16];
	unsigned long long cookie,MysteriousXOR;
	puts("Input your name:");
	read(0, name, 8uLL);
	printf("Hello %s\n", name);

	puts("Input your cookie:");
	scanf("%llu",&cookie);
	MysteriousXOR = (unsigned long long)&buf^0x15CC15CC15CC15CC;
	if(cookie != MysteriousXOR){
		puts("What a damn sham :(");
		_exit(0);
	}
	puts("correct cookie :)");
}

int main(){
	init();
	char data[0x50];
	login();
	puts("I won't be able to see anything in the future :(");
	close(1);
	read(0, data, 0x60uLL);
	return 0;
}
