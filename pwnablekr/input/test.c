#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char *argv[], char *envp[])
{
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	printf("hello: %s\n", buf);
	read(2, buf, 4);
	printf("bye: %s\n", buf);

	return 0;
}
