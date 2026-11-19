// Name: bypass_valid_vtable
// gcc -o bypass_valid_vtable bypass_valid_vtable.c -no-pie

#include <stdio.h>
#include <unistd.h>

FILE *fp;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  init();

  fp = fopen("/dev/urandom", "r");

  printf("stdout: %p\n", stdout);
  printf("Data: ");

  read(0, fp, 300);

  fclose(fp);
}

