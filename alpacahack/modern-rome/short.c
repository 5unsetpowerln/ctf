#include <stdio.h>
int main() {
	short s = -8;
	printf("%x\n", s);

	unsigned short t = -372;
	printf("%hd\n", t);
	printf("%d\n", t);
	return 0;
}
