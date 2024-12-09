#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <uchar.h>

int main() {
  char utf8_ptr[8];
  size_t result = c32rtomb(utf8_ptr, 0x11111111, 0);
  int n = 0x41414141;
  printf("%zu\n", result);
  printf("%lx\n", n + result);
  return 0;
}
