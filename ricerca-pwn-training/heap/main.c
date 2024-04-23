#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NOTE_NUM 4
#define NOTE_MAX_SIZE 0x1000

unsigned g_size[NOTE_NUM];
char *g_note[NOTE_NUM];

/* Input a line of string */
void get_line(const char *msg, char *buf, unsigned size) {
  unsigned i;
  printf("%s", msg);
  for (i = 0; i < size - 1; i++) {
    if (read(STDIN_FILENO, buf + i, 1) != 1) exit(1);
    if (buf[i] == '\n') break;
  }
  buf[i] = '\0';
}

/* Input value */
unsigned get_val(const char *msg) {
  char buf[0x10];
  get_line(msg, buf, sizeof(buf));
  return atol(buf);
}

/* Input and validate index */
unsigned get_index(const char *msg) {
  unsigned index = get_val(msg);
  if (index >= NOTE_NUM) {
    puts("[-] Invalid index");
    exit(1);
  }
  return index;
}

/* Input and validate size */
unsigned get_size(const char *msg) {
  unsigned size = get_val(msg);
  if (size >= NOTE_MAX_SIZE) {
    puts("[-] Invalid size");
    exit(1);
  }
  return size;
}

/* Entry point */
int main(void) {
  unsigned index, size;
  char *p;

  puts("1. new\n2. edit\n3. show\n4. delete");
  while (1) {
    switch (get_val("> ")) {
      case 1: { // new
        index = get_index("Index: ");
        size = get_size("Size: ");
        if (g_note[index])
          puts("[-] Note in use");
        else {
          g_note[index] = (char*)malloc(size);
          g_size[index] = size;
        }
        break;
      }

      case 2: { // edit
        index = get_index("Index: ");
        size = get_size("Size: ");
        if (g_note[index]) {
          if (size <= g_size[index])
            get_line("Data: ", g_note[index], size);
          else
            puts("[-] Invalid size");
        } else
          puts("[-] Empty note");
        break;
      }

      case 3: // show
        index = get_index("Index: ");
        if (g_note[index])
          printf("Note: %s\n", g_note[index]);
        else
          puts("[-] Empty note");
        break;

      case 4: // delete
        index = get_index("Index: ");
        if (g_note[index]) {
          free(g_note[index]);
          g_note[index] = NULL;
          g_size[index] = 0;
        } else
          puts("[-] Empty note");
        break;

      default: return 0;
    }
  }
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
