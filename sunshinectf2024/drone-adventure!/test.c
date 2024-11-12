#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
	char buf[12] = "";

	scanf("%11s", buf);

	if (!strcmp(buf, "password")) {
		printf("hello");
	}

	return 0;
}
