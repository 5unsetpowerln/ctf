#include <stdlib.h>
int main() {
  void *ptr;
  void *ptr1;
  ptr = malloc(0x18);
  ptr1 = malloc(0x18);
  free(ptr);
  free(ptr1);
  return 0;
}
