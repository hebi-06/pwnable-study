// Name: iofile_aar
// gcc -o iofile_aar iofile_aar.c -no-pie

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char flag_buf[1024];
FILE *fp;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int read_flag() {
    FILE *fp;
    fp = fopen("/home/iofile_aar/flag", "r");
    fread(flag_buf, sizeof(char), sizeof(flag_buf), fp);
    fclose(fp);
}

int main() {
  const char *data = "TEST FILE!";

  init();
  read_flag();

  fp = fopen("/tmp/testfile", "w");

  printf("Data: ");

  read(0, fp, 300);

  fwrite(data, sizeof(char), sizeof(flag_buf), fp);
  fclose(fp);
}
