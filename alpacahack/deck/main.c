#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DECK_SIZE (13 * 4)
#define MAKE_CARD(suit, rank) ((((suit)) << 8) | (rank))
#define CARD_SUIT(card) ((card_t)(card) >> 8)
#define CARD_RANK(card) ((card_t)(card) & 0xff)

typedef unsigned short card_t;
typedef struct _game_t {
  void (*shuffle)(card_t*);
  card_t *deck;
  char *name;
} game_t;

const char *suit_symbols[4] = {"♠", "♦", "♥", "♣"};
const char *card_numbers[13] = {"A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"};

void getstr(const char *s, char *buf, size_t len) {
  size_t i;
  printf("%s", s);

  for (i = 0; i < len; i++) {
    if (read(STDIN_FILENO, buf + i, 1) != 1) exit(1);
    if (buf[i] == '\n') break;
  }
  buf[i] = '\0';
}

ssize_t getval(const char *s) {
  ssize_t val;
  printf("%s", s);
  if (scanf("%ld%*c", &val) != 1) exit(1);
  return val;
}

void swap_cards(card_t *deck, size_t i, size_t j) {
  card_t tmp = deck[i];
  deck[i] = deck[j];
  deck[j] = tmp;
}

void shuffle_naive(card_t *deck) {
  size_t i;

  for (i = 0; i < DECK_SIZE * 2; i++)    
    swap_cards(deck, rand() % DECK_SIZE, rand() % DECK_SIZE);
}

void shuffle_knuth(card_t *deck) {
  size_t i, j;

  for (i = DECK_SIZE; i > 0; i--) {
    j = rand() % (i + 1);
    swap_cards(deck, i, j);
  }
}

void shuffle_sattolo(card_t *deck) {
  size_t i, j;

  for (i = 0; i < DECK_SIZE - 1; i++) {
    j = i + 1 + rand() % (DECK_SIZE - i - 1);
    swap_cards(deck, i, j);
  }
}

game_t* game_new() {
  game_t *game;
  char *name = NULL;
  card_t *deck = NULL;

  if (!(deck = (card_t*)malloc(sizeof(card_t) * DECK_SIZE)))
    goto err;
  if (!(name = strdup("Human")))
    goto err;
  if (!(game = (game_t*)malloc(sizeof(game_t))))
    goto err;

  for (size_t i = 0; i < DECK_SIZE; i++)
    deck[i] = MAKE_CARD(i / 13, i % 13);

  game->deck = deck;
  game->name = name;
  game->shuffle = shuffle_naive;
  srand(time(NULL));
  return game;

 err:
  if (name) free(name);
  if (deck) free(deck);
  return NULL;
}

void game_del(game_t *game) {
  free(game->deck);
  free(game->name);
  free(game);
}

void game_play(game_t *game) {
  printf("Challenger: %s\n", game->name);
  game->shuffle(game->deck);

  card_t card = game->deck[0];

  size_t suit = getval("Guess the suit (1=♠ / 2=♦ / 3=♥ / 4=♣): ");
  size_t num  = getval("Guess the number (1-13): ");

  printf("The card: %s%s\n",
         suit_symbols[CARD_SUIT(card)],
         card_numbers[CARD_RANK(card)]);

  if (suit == CARD_SUIT(card) + 1)
    puts("Your guess on the suit is correct!");
  else
    puts("Your guess on the suit is wrong...");

  if (num == CARD_RANK(card) + 1)
    puts("Your guess on the number is correct!");
  else
    puts("Your guess on the number is wrong...");
}

int main() {
  game_t *game;

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (!(game = game_new())) {
    puts("[-] Cannot create a game");
    return 1;
  }

  while (1) {
    puts("1. Play a game\n"
         "2. Change shuffle method\n"
         "3. Change your name");
    switch (getval("> ")) {
      case 1:
        game_play(game);
        break;

      case 2: {
        size_t choice = getval("1=Naive / 2=Fisher-Yates / 3=Sattolo: ");
        if (choice == 1)
          game->shuffle = shuffle_naive;
        else if (choice == 2)
          game->shuffle = shuffle_knuth;
        else
          game->shuffle = shuffle_sattolo;
        break;
      }

      case 3: {
        char *name;
        size_t len = getval("Length: ");

        if (len > 0x1000) {
          puts("[-] Invalid length");
          break;
        }

        if (!(name = (char*)malloc(len + 1))) {
          puts("[-] Cannot allocate memory");
          break;
        }

        getstr("Name: ", name, len);

        free(game->name);
        game->name = name;
        break;
      }

      default:
        game_del(game);
        return 0;
    }
  }
}
