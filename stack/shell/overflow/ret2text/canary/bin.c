//gcc -z now -no-pie bin.c -o bin
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void getshell(void) {
    system("/bin/sh");
}

void init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vul(void) {
    char buffer[0x60];
    read(STDIN_FILENO, buffer, 0x80);
}

int main(void) {
    init();
	pid_t pid;
	while(1) {
		pid = fork();
		if(pid < 0) {
			puts("fork error :(");
			exit(0);
		}
		else if(pid == 0) {
			puts("Please pwn me :)");
			vul();
			puts("recv sucess");
		}
		else {
			wait(0);
		}
	}
}