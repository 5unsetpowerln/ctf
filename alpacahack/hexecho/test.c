#include <stdio.h>
#include <string.h>
int main() {
  char buf[0x100];
  
  strcpy(&buf[0], "hello world!\x00");
  printf("%s\n", &buf[0]);
  scanf("%02hhx", buf);
  printf("%s\n", &buf[0]);

  return 1;
}
