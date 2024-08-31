#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUF_SIZE 0x100

int get_size() {
  int size = 0;
  scanf("%d%*c", &size);
  return size;
}

void get_hex(char *buf, unsigned size) {
  for (unsigned i = 0; i < size; i++)
    scanf("%02hhx", buf + i);
}

void hexecho() {
  int size;
  char buf[BUF_SIZE];

  // Input size
  printf("Size: ");
  size = get_size();

  // Input data
  printf("Data (hex): ");
  get_hex(buf, size);

  // Show data
  printf("Received: ");
  for (int i = 0; i < size; i++)
    printf("%02hhx ", (unsigned char)buf[i]);
  putchar('\n');
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  hexecho();
  return 0;
}
