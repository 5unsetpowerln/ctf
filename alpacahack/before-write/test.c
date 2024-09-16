#include <stdio.h>
int main() {
    char buf[0x20] = {};
    printf("%lu\n", sizeof(buf));
    return 0;
}
