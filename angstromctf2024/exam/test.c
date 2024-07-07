#include <stdint.h>
#include <stdio.h>
int main() {
  // uint32_t buf = 0x7fffffff;
  uint32_t buf = 0 - 0x7fffffff;
  // uint32_t buf1 = 1;
  // buf -= buf1;
  // char buf[100] = "hello";
  printf("buf: %x\n", buf);
  return 0;
}
