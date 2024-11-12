#include <stdio.h>
const char suffix[] = "! Welcome to IrisCTF2024. If you have any questions you "
					  "can contact us at test@example.com\0\0\0\0";

int main() {
	printf("%lu\n", sizeof(suffix));
	return 0;
}
