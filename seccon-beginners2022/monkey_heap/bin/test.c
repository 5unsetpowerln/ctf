#include <stdlib.h>
int main() {
  void *buf1 = calloc(0x68, 1);
  free(buf1);
  void *buf2 = calloc(0x68, 1);
  free(buf2);
  void *buf3 = calloc(0x68, 1);
  free(buf3);
  void *buf4 = calloc(0x68, 1);
  free(buf4);
  void *buf5 = calloc(0x68, 1);
  free(buf5);
  void *buf6 = calloc(0x68, 1);
  free(buf6);
  void *buf7 = calloc(0x68, 1);
  free(buf7);
  void *buf = calloc(0x68, 1);
  free(buf);
  return 1;
}
