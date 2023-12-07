//gcc -o OBN35 OBN35.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

int Nodes_len[0x20];
char *Nodes[0x20];
int count=0;
int get_atoi(){
	char buf[8];
	read(0,buf,8);	
	return atoi(buf);
}
void sandbox(){
	struct sock_filter filter[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,(offsetof(struct seccomp_data,arch))),
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
void add(){
	int len;
	printf("len:");
	scanf("%d",&len);
	if(len < 0||len > 0xfff){
		puts("size error :(");
		_exit(0);
	}
	if(count > 31){
		puts("too many :(");
		_exit(0);
	}
	Nodes[count] = malloc(len);
	Nodes_len[count] = len;
	puts("please input content:");
	read(0,Nodes[count],len);
	count++;
	puts("done :)");
}
void del(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count||!Nodes[idx]){
		puts("error :(");
		_exit(0);
	}
	free(Nodes[idx]);
	Nodes[idx] = NULL;
	puts("done :)");	
}
void edit(){
	int idx,len;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count||!Nodes[idx]){
		puts("error :(");
		_exit(0);
	}
	len = read(0,Nodes[idx],Nodes_len[idx]);
	Nodes[idx][len] = '\x00'; //off by null
	puts("done :)");
}
void show(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count||!Nodes[idx]){
		puts("error :(");
		_exit(0);
	}
	write(1,Nodes[idx],Nodes_len[idx]);
}
void menu(){
	puts("Welcome :-)");
	puts("1.add");
	puts("2.delete");
	puts("3.edit");
	puts("4.show");
	puts("5.exit");
	printf("choice:");
}
void init(){
	setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
}
int main(){
	int choice;
	init();
	sandbox();
	while(1){
		menu();
		choice = get_atoi();
		switch(choice){
			case 1:
				add();
				break;
			case 2:
				del();
				break;
			case 3:
				edit();
				break;
			case 4:
				show();
				break;
			case 5:
				_exit(0);
			default:
				puts("invalued input :(");
				_exit(0);
		}
	}
	return 0;
} 
