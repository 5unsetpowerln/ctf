// #include <iostream>
#include <unistd.h>

int main() {
  char buf;
  read(0, &buf, 0x40);
  // read
  return 1;
}
