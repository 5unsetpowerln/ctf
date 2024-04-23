#include <stdlib.h>

void main(void)
{
  char *p0, *p1;

  p0 = malloc(0x10);
  p1 = malloc(0x500);

  free(p1);
}
