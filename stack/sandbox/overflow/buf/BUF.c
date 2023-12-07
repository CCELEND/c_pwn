//gcc -o BUF BUF.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

void sandbox(){
    struct sock_filter filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4),
    BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,2),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
    BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
    BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
    BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}

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
	sandbox();
    init();
    login();
    printf("Please pwn me :)\n");
    vuln();
    return 0;
}


