
#include <stdio.h>
#include <string.h>
int main() {
    char dest[100] = "echo                   cat_flag\n";
    strcpy(dest, dest + 9);
    printf("%s", dest);
    return 0;
}
