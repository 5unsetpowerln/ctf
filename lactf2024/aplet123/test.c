#include <stdio.h>
#include <string.h>
const char *const responses[] = {"L",
								 "amongus",
								 "true",
								 "pickle",
								 "GINKOID",
								 "L bozo",
								 "wtf",
								 "not with that attitude",
								 "increble",
								 "based",
								 "so true",
								 "monka",
								 "wat",
								 "monkaS",
								 "banned",
								 "holy based",
								 "daz crazy",
								 "smh",
								 "bruh",
								 "lol",
								 "mfw",
								 "skissue",
								 "so relatable",
								 "copium",
								 "untrue!",
								 "rolled",
								 "cringe",
								 "unlucky",
								 "lmao",
								 "eLLe",
								 "loser!",
								 "cope",
								 "I use arch btw"};

int main() {
	// const int i0 = sizeof responses;
	// const int i1 = sizeof responses[0];
	// const int i2 = sizeof responses / sizeof responses[0];
	// printf("%d\n", i0);
	// printf("%d\n", i1);
	// printf("%d\n", i2);
	char *s = "AAAAi'm\0BBBB";
	char *ss = strstr(s, "i'm");
	printf("%s", ss);
	return 0;
}
