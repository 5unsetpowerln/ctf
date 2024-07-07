#include <stdint.h>
#include <stdio.h>
int main(int argc, char *argv[])
{
  uint32_t i = 1;
  i += 0xffffffff;
  printf("%d\n", i);
  return 0;
}
