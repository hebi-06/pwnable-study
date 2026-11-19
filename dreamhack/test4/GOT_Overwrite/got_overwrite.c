// Name: got_overwrite.c
// Compile: gcc -o got_overwrite got_overwrite.c -ldl -no-pie -fno-PIE -Wl,-z,norelro
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
  char command[0x40] = {0};
  void *where = NULL;

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("puts: %p\n", dlsym(RTLD_DEFAULT, "puts"));

  printf("command: ");
  read(0, command, sizeof(command) - 1);

  printf("where: ");
  read(0, &where, sizeof(where));

  printf("value: ");
  read(0, where, 8);

  puts(command);
  return 0;
}
