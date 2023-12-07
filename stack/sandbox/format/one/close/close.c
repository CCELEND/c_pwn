//gcc close.c -o close -lseccomp
//Ubuntu18
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

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
    printf(data);
    return 0;
}
