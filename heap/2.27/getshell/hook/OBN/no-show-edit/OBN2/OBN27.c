//gcc -o OBN27 OBN27.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int Nodes_len[0x20];
char *Nodes[0x20];
int count=0;
int get_atoi()
{
	char buf[10];
	read(0,buf,10);	
	return atoi(buf);
}

void add(){
	int len;
	if(count>31){
		puts("too many :(");
		exit(0);
	}
	printf("len:");
	scanf("%d",&len);
	if(len<0||len>0x100){
		puts("size error :(");
		exit(0);
	}
	Nodes[count] = malloc(len);
	Nodes_len[count] = len;
	printf("data:");
	read(0,Nodes[count],len);
	Nodes[count][len] = '\x00';
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

void menu(){
	puts("Welcome :-)");
	puts("1.add");
	puts("2.delete");
	puts("3.exit");
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
				exit(0);
			default:
				puts("invalued input :(");
				exit(0); 
		}
	}
	return 0;
} 
