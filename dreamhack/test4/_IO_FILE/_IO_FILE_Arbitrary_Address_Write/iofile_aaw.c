// Name: iofile_aaw
// gcc -o iofile_aaw iofile_aaw.c -no-pie 

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char flag_buf[1024];
int overwrite_me;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int read_flag() {
  FILE *fp;
  fp = fopen("/home/iofile_aaw/flag", "r");
  fread(flag_buf, sizeof(char), sizeof(flag_buf), fp);

  write(1, flag_buf, sizeof(flag_buf));
  fclose(fp);
}

int main() {
  FILE *fp;

  char file_buf[1024];

  init();

  fp = fopen("/etc/issue", "r");

  printf("Data: ");

  read(0, fp, 300);

  fread(file_buf, 1, sizeof(file_buf)-1, fp);

  printf("%s", file_buf);

  if( overwrite_me == 0xDEADBEEF) 
    read_flag();

  fclose(fp);
}
