#include <stdint.h>
#include <stdio.h>
int main() {
  int64_t *da;
  *da = 0xffffffffffffffff;
  printf("%d\n", da);
  return 0;
}
