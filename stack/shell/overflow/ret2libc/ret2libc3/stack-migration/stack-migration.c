//gcc -fno-stack-protector -no-pie -z now stack-migration.c -o stack-migration 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void main() {
    char buf[0x28];
    puts("Please pwn me :)");
    read(0, buf, 0x40);
}