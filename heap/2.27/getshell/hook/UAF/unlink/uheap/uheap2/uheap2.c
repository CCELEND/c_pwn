//gcc -o uheap2 uheap2.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int Nodes_len[6];
char *Nodes[6];
char *sentence_chunk;
int count=0;
int get_atoi()
{
	char buf[6];
	read(0,buf,6);
	return atoi(buf);
}

void add(){
	int len,idx;
	printf("Index:");
	scanf("%d",&idx);
	if(count>10||idx>5){
		puts("Incorrect quantity :(");
		_exit(0);
	}
	printf("len:");
	scanf("%d",&len);
	if(len<0x20||len>0x88){
		puts("Incorrect size :(");
		_exit(0);
	}
	Nodes[idx] = malloc(len);
	if( ((unsigned long)Nodes[idx]&0xFFFFFFFFFFFFF000) != (unsigned long)sentence_chunk-0x250 ){
		puts("You're in a wrong place to go :(");
		_exit(0);
	}
	Nodes_len[idx] = len;
	count++;
	puts("done :)");
}

void del(){
	int idx;
	printf("Index:");
	scanf("%d",&idx);
	if(idx>5||!Nodes[idx]){
		puts("Incorrect subscript :(");
		_exit(0);
	}
	free(Nodes[idx]); //UAF
	puts("done :)");	
}

void edit(){
	int idx;
	printf("Index:");
	scanf("%d",&idx);
	if(idx>5||!Nodes[idx]){
		puts("Incorrect subscript :(");
		_exit(0);
	}
	read(0,Nodes[idx],Nodes_len[idx]);
	puts("done :)");
}

void show(){
	int idx;
	printf("Index:");
	scanf("%d",&idx);
	if(idx>5||!Nodes[idx]){
		puts("Incorrect subscript :(");
		_exit(0);
	}
	write(1,Nodes[idx],Nodes_len[idx]);
}

void menu(){
	puts("Welcome to ISCC :-)");
	puts("1.add");
	puts("2.delete");
	puts("3.edit");
	puts("4.show");
	puts("5.exit");
	printf("choice:");
}

void init() {
	setvbuf(stdin,  0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
}

void login(){
	char *sentence;
	char name[16];
	unsigned long long cookie,MysteriousXOR;
	puts("Input your name:");
	read(0, name, 8uLL);
	printf("Hello %s\n", name);

	puts("Input your favorite sentence:");
	sentence = malloc(0x30);
	read(0,sentence,0x30);
	sentence_chunk = sentence - 0x10;

	puts("Input your cookie:");
	scanf("%llu",&cookie);
	MysteriousXOR = (unsigned long long)&sentence_chunk^0x15CC15CC15CC15CC;
	if(cookie != MysteriousXOR){
		puts("What a damn sham :(");
		_exit(0);
	}
	puts("correct cookie :)");
}

int main(){
	init();
	login();
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
				puts("bye~");
				_exit(0);
			default:
				puts("invaild choice :(");
				break; 
		}
	}
	return 0;
} 
