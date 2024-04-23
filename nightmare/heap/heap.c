#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(void)
{
    char *ptr;

    ptr = malloc(0x10);

    strcpy(ptr, "panda");
}
