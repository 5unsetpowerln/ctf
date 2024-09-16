#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef unsigned short card_t;
typedef struct _game_t {
  void (*shuffle)(card_t *);
  card_t *deck;
  char *name;
} game_t;

#define DECK_SIZE (13 * 4)

int main() {

  // char *buf;
  // buf = malloc(0x20);
  // strncpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0x20);
  // read(STDIN_FILENO, buf, 0x20);
  // printf("%s\n", buf);

  // srand(time(NULL));
  srand(1);
  int r;
  for (size_t i = 13 * 4; i > 0; i--) {
    r = rand();
    printf("%d\n", r);
  }
  // size_t i, j, r;

  // for (i = 13 * 4; i > 0; i--) {
  //   r = rand();
  //   j = r % (i + 1);
  //   printf("%d %d %d\n", i, j, r);
  // }

  // // for (i = 0; i < DECK_SIZE *2; i++)
  // //   printf("%d %d\n", rand() % DECK_SIZE, rand() % DECK_SIZE);
  // for (i = 0; i < DECK_SIZE - 1; i++) {
  //   j = i + 1 + rand() % (DECK_SIZE - i - 1);
  //   printf("%d %d\n", i, j);
  // }
  return 1;
}
