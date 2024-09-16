#include <stdio.h>
#include <string.h>
int main(int argc, char *argv[])
{
  int r = strcmp("\x00", "\x00 AAA");
  printf("%d\n", r);
  return 0;
}
