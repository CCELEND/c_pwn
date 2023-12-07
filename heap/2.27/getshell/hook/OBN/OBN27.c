//gcc -o OBN27 OBN27.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int Nodes_len[0x11];
char *Nodes[0x11];
int count=0;
int get_atoi()
{
	char buf[8];
	read(0,buf,8);	
	return atoi(buf);
}

void add(){
	int len;
	printf("len:");
	scanf("%d",&len);
	if(len<0||len>0x100){
		puts("size error :(");
		exit(0);
	}
	if(count>16){
		puts("too many :(");
		exit(0);
	}
	Nodes[count] = malloc(len);
	Nodes_len[count] = len;
	count++;
	puts("done :)");
}

void del(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count||!Nodes[idx]){
		puts("error :(");
		exit(0);
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
		exit(0);
	}
	len = read(0,Nodes[idx],Nodes_len[idx]);
	Nodes[idx][len] = '\x00';   //off by null
	puts("done :)");
}

void show(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count||!Nodes[idx]){
		puts("error :(");
		exit(0);
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
				show();
				break;
			case 5:
				exit(0);
			default:
				puts("invalued input :(");
				exit(0); 
		}
	}
	return 0;
} 
