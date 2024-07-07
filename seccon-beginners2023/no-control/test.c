#include <stdio.h>
#include <stdlib.h>
int main() {
  int idx = 0;
  char buf[0x100];
  fgets(buf, 0xff, stdin);
  idx = atoi(buf);
  printf("%d\n", idx);
  return 0;
}
