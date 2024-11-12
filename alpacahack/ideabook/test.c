#include <stdio.h>
int main() {
  int a = ~(2 | 0x8 | 0x800);
  printf("%x\n", a);
  return 0;
}
