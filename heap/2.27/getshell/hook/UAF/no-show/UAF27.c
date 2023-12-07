//gcc -o UAF27 UAF27.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int Nodes_len[6];
char *Nodes[6];
int count=0;
int get_atoi()
{
	char buf[10];
	read(0,buf,10);	
	return atoi(buf);
}

void add(){
	int len,idx;
	printf("idx:");
	scanf("%d",&idx);
	if(count>0x10||idx>5){
		puts("too many :(");
		exit(0);
	}
	printf("len:");
	scanf("%d",&len);
	if(len<0x20||len>0x88){
		puts("size error :(");
		exit(0);
	}
	Nodes[idx] = malloc(len);
	Nodes_len[idx] = len;
	count++;
	puts("done :)");
}

void del(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>5||!Nodes[idx]){
		puts("error :(");
		exit(0);
	}
	free(Nodes[idx]); //UAF
	puts("done :)");	
}

void edit(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>5||!Nodes[idx]){
		puts("error :(");
		exit(0);
	}
	read(0,Nodes[idx],Nodes_len[idx]);
	puts("done :)");
}

void menu(){
	puts("Welcome :-)");
	puts("1.add");
	puts("2.delete");
	puts("3.edit");
	puts("4.exit");
	printf("choice:");
}

void init() {
	setvbuf(stdin,  0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
}

int main(){
	init();
	while(1){
		int choice;
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
				exit(0);
			default:
				puts("invalued input :(");
				exit(0); 
		}
	}
	return 0;
} 
