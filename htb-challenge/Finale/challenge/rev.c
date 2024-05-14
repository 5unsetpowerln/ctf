#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
  int64_t random_buf = 0;
  int fd = open("/dev/urandom", 0);
  read(fd, &random_buf, 8);
  printf("\n[Strange man in mask screams s…", &buf);
}
