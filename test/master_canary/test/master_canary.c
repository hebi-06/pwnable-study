// Name: master_canary.c
// Compile: gcc -o master_canary master_canary.c -no-pie
#include <stdio.h>
#include <unistd.h>
int main()
{
	char buf[256];
	read(0, buf, 256);
}

