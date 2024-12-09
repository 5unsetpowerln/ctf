#include <stdio.h>
#include <stdlib.h>
int main() {
	system("AAAAAAAA\x00/bin/sh");
	return 0;
}
