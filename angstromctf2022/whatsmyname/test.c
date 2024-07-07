#include <stdio.h>
#include <string.h>
int main() {
  char buf[8] = "aaaaaaaa";
  char buf2[8] = "\x00";

  int r = strncmp(buf, buf2, 8);
  printf("%d", r);
}
