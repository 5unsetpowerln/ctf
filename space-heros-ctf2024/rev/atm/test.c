#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
  int32_t random;
  srand(time(NULL));
  random = rand();

  printf("%x\n", random);

  return 0;
}
