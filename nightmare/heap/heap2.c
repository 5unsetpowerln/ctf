#include <stdlib.h>

void main(void) {
  char *p0, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9;

  p1 = malloc(0x200);
  p2 = malloc(0x200);
  p3 = malloc(0x200);
  p4 = malloc(0x200);
  p5 = malloc(0x200);
  p6 = malloc(0x200);
  p7 = malloc(0x200);
  p8 = malloc(0x200);

  malloc(10); // Here to avoid consolidation with Top Chunk

  free(p1);
  free(p2);
  free(p3);
  free(p4);
  free(p5);
  free(p6);
  free(p7);
  free(p8);

  malloc(0x1000);
}
