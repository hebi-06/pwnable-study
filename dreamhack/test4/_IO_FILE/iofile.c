// Name: iofile.c
// Compile: gcc -o iofile iofile.c

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void file_info(FILE *buf) {
  printf("_flags: %x\n", buf->_flags);
  printf("_fileno: %d", buf->_fileno);
}

int main() {
  FILE *fp;
  char buf[256];
  strcpy(buf, "THIS IS TESTFILE!");
  fp = fopen("testfile", "w");
  fwrite(buf, 1, strlen(buf), fp);

  file_info(fp);

  fclose(fp);
  return 0;
}