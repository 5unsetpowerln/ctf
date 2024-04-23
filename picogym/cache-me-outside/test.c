#include <stdint.h>
#include <stdio.h>

int main() {
  int32_t a;
  scanf("%d", &a);

  fflush(stdin);
  printf("%x\n", a);

  return 0;
}
